"""
tgs_node.py
===========
Ticket Granting Server (TGS) node for the Threshold Kerberos system.

Mirrors the AS node but operates in Phase 2 of the protocol:
  - Accepts a TGT (already threshold-signed) as proof of identity
  - Verifies the TGT's threshold signature against the master public key
  - Issues a partial signature on a new Service Ticket
  - Supports key rotation via RELOAD command

Wire protocol (newline-delimited JSON over TCP):
  Request (Phase 1 — commitment):
    {"cmd": "TGS", "tgt_payload": "...(hex)...",
     "tgt_R": "0x...", "tgt_s": "0x...", "tgt_version": "v1",
     "service_ticket_payload": "...(hex)...", "version": "v1"}
  Response:
    {"status": "commitment", "node_index": 2, "R_i": "0x...",
     "k_i_enc": "...", "version": "v1"}

  Request (Phase 2 — partial signature):
    { ...same as above..., "R_global": "0x...", "k_i_enc": "..." }
  Response:
    {"status": "ok", "node_index": 2, "R_i": "0x...",
     "s_i": "0x...", "version": "v1"}
"""

import os
import sys
import json
import socket
import threading
import secrets
import argparse

from crypto_utils import (
    SchnorrParams,
    modpow,
    secure_random_zq,
    shamir_partial_sign,
    lagrange_coeff,
    hash_message_R,
    verify_threshold_signature,
    aes256_cbc_encrypt,
    aes256_cbc_decrypt,
    sha256_bytes,
    hex_to_int,
    int_to_hex,
    bytes_to_hex,
    hex_to_bytes,
)


class TGSNode:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.lock = threading.Lock()
        self._load_config()

    def _load_config(self):
        with open(self.config_path) as f:
            cfg = json.load(f)
        self.node_index = cfg["node_index"]
        self.port       = cfg["port"]
        p = hex_to_int(cfg["params"]["p"])
        q = hex_to_int(cfg["params"]["q"])
        g = hex_to_int(cfg["params"]["g"])
        self.params  = SchnorrParams(p, q, g)
        self.shares  = {vid: hex_to_int(xs) for vid, xs in cfg["key_shares"].items()}
        self.latest  = cfg["_latest"]
        self.expired = cfg.get("_expired", [])
        print(f"[TGS{self.node_index}] Loaded config: latest version = {self.latest}")

    def reload(self):
        with self.lock:
            self._load_config()
            print(f"[TGS{self.node_index}] Keys reloaded.")

    def get_share(self, version: str):
        with self.lock:
            return self.shares.get(version), self.latest, self.expired

    def get_pubkey(self, version: str) -> int:
        # TGS nodes do NOT hold the full master public key in this config —
        # they only know their share's public counterpart.
        # For TGT verification we need the master pubkey; it is loaded
        # separately from pubkeys.json placed in the same directory.
        pubkeys_path = os.path.join(os.path.dirname(self.config_path),
                                    "..", "pubkeys.json")
        pubkeys_path = os.path.normpath(pubkeys_path)
        if os.path.exists(pubkeys_path):
            with open(pubkeys_path) as f:
                data = json.load(f)
            return hex_to_int(data[version])
        # Fallback: derive from own public share dict in config
        return None


def handle_client(conn: socket.socket, addr, node: TGSNode):
    try:
        data = b""
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break

        request = json.loads(data.decode().strip())
        cmd = request.get("cmd", "")

        if cmd == "RELOAD":
            node.reload()
            _send(conn, {"status": "ok", "message": "Keys reloaded"})
            return

        if cmd != "TGS":
            _send(conn, {"status": "error", "reason": f"Unknown command: {cmd}"})
            return

        # ── Verify the presented TGT ───────────────────────────────────────
        tgt_payload_hex = request.get("tgt_payload", "")
        tgt_R_hex       = request.get("tgt_R", "")
        tgt_s_hex       = request.get("tgt_s", "")
        tgt_version     = request.get("tgt_version", node.latest)

        if not all([tgt_payload_hex, tgt_R_hex, tgt_s_hex]):
            _send(conn, {"status": "error", "reason": "Missing TGT fields"})
            return

        # Check TGT key version
        _, _, expired_list = node.get_share(tgt_version)
        if tgt_version in expired_list:
            _send(conn, {"status": "error",
                         "reason": f"TGT key version {tgt_version} is expired"})
            return

        tgt_bytes = hex_to_bytes(tgt_payload_hex)
        tgt_R     = hex_to_int(tgt_R_hex)
        tgt_s     = hex_to_int(tgt_s_hex)

        y_master = node.get_pubkey(tgt_version)
        if y_master is None:
            _send(conn, {"status": "error",
                         "reason": "Cannot locate master public key for TGT verification"})
            return

        if not verify_threshold_signature(node.params, y_master, tgt_bytes, tgt_R, tgt_s):
            _send(conn, {"status": "error", "reason": "TGT signature verification FAILED"})
            return

        # ── Sign the service ticket ────────────────────────────────────────
        st_version = request.get("version", node.latest)
        x_share, latest, expired = node.get_share(st_version)
        if x_share is None:
            _send(conn, {"status": "error",
                         "reason": f"Unknown key version: {st_version}"})
            return
        if st_version in expired:
            _send(conn, {"status": "error",
                         "reason": f"Key version {st_version} is expired"})
            return

        st_payload_hex = request.get("service_ticket_payload", "")
        if not st_payload_hex:
            _send(conn, {"status": "error", "reason": "Missing service_ticket_payload"})
            return
        st_bytes = hex_to_bytes(st_payload_hex)

        params = node.params
        k_i = secure_random_zq(params.q)
        R_i = modpow(params.g, k_i, params.p)

        R_global_hex = request.get("R_global", None)
        username     = request.get("username", "unknown")

        if R_global_hex is None:
            # Phase 1: return commitment
            _send(conn, {
                "status":     "commitment",
                "node_index": node.node_index,
                "R_i":        int_to_hex(R_i),
                "k_i_enc":    _encrypt_nonce(k_i, username, st_version),
                "version":    st_version,
            })
            return

        # Phase 2: compute partial signature
        R_global = hex_to_int(R_global_hex)
        e = hash_message_R(st_bytes, R_global)

        k_i_enc = request.get("k_i_enc", "")
        k_i_recovered = _decrypt_nonce(k_i_enc, username, st_version)
        if k_i_recovered is None:
            _send(conn, {"status": "error", "reason": "Invalid nonce token"})
            return

        partner_index = int(request.get("partner_index", 0))
        if partner_index == 0 or partner_index == node.node_index:
            _send(conn, {"status": "error", "reason": "Invalid partner_index"})
            return
        s_i = shamir_partial_sign(params, x_share, node.node_index, partner_index, k_i_recovered, e)

        _send(conn, {
            "status":     "ok",
            "node_index": node.node_index,
            "R_i":        int_to_hex(R_i),
            "s_i":        int_to_hex(s_i),
            "version":    st_version,
        })

    except json.JSONDecodeError:
        _send(conn, {"status": "error", "reason": "Malformed JSON"})
    except Exception as exc:
        _send(conn, {"status": "error", "reason": str(exc)})
    finally:
        conn.close()


# ── Nonce helpers (identical scheme to AS node) ────────────────────────────────

def _encrypt_nonce(k_i: int, username: str, version: str) -> str:
    key = sha256_bytes(b"tgs-nonce" + username.encode() + version.encode())
    from crypto_utils import aes256_cbc_encrypt
    plaintext = k_i.to_bytes(64, "big") + sha256_bytes(k_i.to_bytes(64, "big"))
    return bytes_to_hex(aes256_cbc_encrypt(key, plaintext))


def _decrypt_nonce(token_hex: str, username: str, version: str):
    if not token_hex:
        return None
    try:
        key = sha256_bytes(b"tgs-nonce" + username.encode() + version.encode())
        raw = aes256_cbc_decrypt(key, hex_to_bytes(token_hex))
        k_bytes  = raw[:64]
        checksum = raw[64:96]
        if checksum != sha256_bytes(k_bytes):
            return None
        return int.from_bytes(k_bytes, "big")
    except Exception:
        return None


def _send(conn: socket.socket, obj: dict):
    conn.sendall((json.dumps(obj) + "\n").encode())


def run_server(config_path: str):
    node = TGSNode(config_path)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", node.port))
    srv.listen(16)
    print(f"[TGS{node.node_index}] Listening on 127.0.0.1:{node.port} …")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, node), daemon=True)
        t.start()


def main():
    parser = argparse.ArgumentParser(description="TGS node")
    parser.add_argument("config", help="Path to node_config.json")
    args = parser.parse_args()
    run_server(args.config)


if __name__ == "__main__":
    main()
