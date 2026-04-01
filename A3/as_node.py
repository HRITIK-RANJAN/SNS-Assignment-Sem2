"""
as_node.py
==========
Authentication Server (AS) node for the Threshold Kerberos system.

Each AS node:
  1. Loads its private key share(s) from node_config.json
  2. Listens on its assigned TCP port
  3. On receiving an auth request:
       - Verifies client credentials (username + HMAC-based password check)
       - Generates a fresh nonce k_i and commitment R_i = g^k_i mod p
       - Signs the ticket payload with its partial key share
       - Returns (R_i, s_i, session_key_encrypted) to the client
  4. Supports RELOAD command for key rotation (SIGHUP or explicit message)

Wire protocol (newline-delimited JSON over TCP):
  Request:
    {"cmd": "AUTH", "username": "...", "password_hash": "...",
     "ticket_payload": "...(hex)...", "version": "v1"}
  Response (success):
    {"status": "ok", "node_index": 1, "R": "0x...", "s": "0x...",
     "session_key_enc": "...(hex)...", "version": "v1"}
  Response (error):
    {"status": "error", "reason": "..."}

  Request:
    {"cmd": "RELOAD"}
  Response:
    {"status": "ok", "message": "Keys reloaded"}
"""

import os
import sys
import json
import socket
import threading
import secrets
import hashlib
import argparse
import time

from crypto_utils import (
    SchnorrParams,
    modpow,
    secure_random_zq,
    shamir_partial_sign,
    lagrange_coeff,
    hash_message_R,
    aes256_cbc_encrypt,
    sha256_bytes,
    sha256_int,
    hex_to_int,
    int_to_hex,
    bytes_to_hex,
    hex_to_bytes,
)

# ── Hard-coded user credentials (demo) ────────────────────────────────────────
# In production these would be in a secure directory-service database.
# Password stored as SHA-256(username + ":" + password).
USERS = {
    "alice": hashlib.sha256(b"alice:wonderland").hexdigest(),
    "bob":   hashlib.sha256(b"bob:builder").hexdigest(),
    "carol": hashlib.sha256(b"carol:s3cr3t").hexdigest(),
}

# ── Node state (loaded from config) ───────────────────────────────────────────
class ASNode:
    def __init__(self, config_path: str, malicious: bool = False):
        self.config_path = config_path
        self.malicious   = malicious          # Attack 1: corrupt partial sig
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
        print(f"[AS{self.node_index}] Loaded config: latest version = {self.latest}")

    def reload(self):
        with self.lock:
            self._load_config()
            print(f"[AS{self.node_index}] Keys reloaded.")

    def get_share(self, version: str):
        with self.lock:
            return self.shares.get(version), self.latest, self.expired

    def get_params(self) -> SchnorrParams:
        return self.params


# ── Request handler ────────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr, node: ASNode):
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
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

        if cmd != "AUTH":
            _send(conn, {"status": "error", "reason": f"Unknown command: {cmd}"})
            return

        # ── Authenticate user ──────────────────────────────────────────────
        username      = request.get("username", "")
        password_hash = request.get("password_hash", "")
        version       = request.get("version", node.latest)

        if username not in USERS:
            _send(conn, {"status": "error", "reason": "Unknown user"})
            return

        expected = USERS[username]
        # Constant-time comparison to resist timing attacks
        if not secrets.compare_digest(expected, password_hash):
            _send(conn, {"status": "error", "reason": "Authentication failed"})
            return

        # ── Version check ──────────────────────────────────────────────────
        x_share, latest, expired = node.get_share(version)
        if x_share is None:
            _send(conn, {"status": "error",
                         "reason": f"Unknown key version: {version}"})
            return
        if version in expired:
            _send(conn, {"status": "error",
                         "reason": f"Key version {version} has been rotated/expired"})
            return

        # ── Build & sign ticket payload ────────────────────────────────────
        ticket_payload_hex = request.get("ticket_payload", "")
        if not ticket_payload_hex:
            _send(conn, {"status": "error", "reason": "Missing ticket_payload"})
            return

        ticket_bytes = hex_to_bytes(ticket_payload_hex)
        params = node.get_params()

        # Fresh nonce (MUST be unique per signing operation — nonce reuse
        # leaks the private share; see SECURITY.md)
        k_i = secure_random_zq(params.q)
        R_i = modpow(params.g, k_i, params.p)

        # The client will later combine R_i * R_j to get global R, then
        # compute e = H(m || R_global).  However, for the partial signature
        # each AS must use the SAME global challenge e, which means the
        # client must do a two-round protocol or provide R_global.
        #
        # We use the single-round approach: client sends R_global in the
        # request (pre-computed from its own nonce), and each AS uses that
        # to compute e.  Each AS also sends back R_i so the client can
        # verify R_global = R_i * R_j mod p.
        #
        # If R_global is not supplied (first contact), we return R_i only
        # and wait for the client to aggregate and re-request.

        R_global_hex = request.get("R_global", None)

        if R_global_hex is None:
            # Phase 1 of 2-round protocol: return commitment only
            _send(conn, {
                "status":     "commitment",
                "node_index": node.node_index,
                "R_i":        int_to_hex(R_i),
                "k_i_enc":    _encrypt_nonce(k_i, username, version),
                "version":    version,
            })
            return

        # Phase 2: client sends R_global; compute challenge and partial sig
        R_global = hex_to_int(R_global_hex)
        e = hash_message_R(ticket_bytes, R_global)

        # Recover k_i from encrypted nonce token (sent back by client)
        k_i_enc = request.get("k_i_enc", "")
        k_i_recovered = _decrypt_nonce(k_i_enc, username, version)
        if k_i_recovered is None:
            _send(conn, {"status": "error", "reason": "Invalid nonce token"})
            return

        partner_index = int(request.get("partner_index", 0))
        if partner_index == 0 or partner_index == node.node_index:
            _send(conn, {"status": "error", "reason": "Invalid partner_index"})
            return
        s_i = shamir_partial_sign(params, x_share, node.node_index, partner_index, k_i_recovered, e)

        # ── MALICIOUS MODE: corrupt the partial signature ──────────────────
        # Simulates a compromised AS returning a random s_i that will fail
        # the client's per-node partial-signature verification check.
        if node.malicious:
            s_i = secure_random_zq(params.q)
            print(f"[AS{node.node_index}] *** MALICIOUS: sending forged s_i ***")

        # Session key: random 32-byte AES key, encrypted under a KDF of
        # (username, node_index, version, timestamp)
        session_key     = secrets.token_bytes(32)
        session_key_enc = _encrypt_session_key(session_key, username, version)

        _send(conn, {
            "status":          "ok",
            "node_index":      node.node_index,
            "R_i":             int_to_hex(R_i),
            "s_i":             int_to_hex(s_i),
            "session_key_enc": bytes_to_hex(session_key_enc),
            "version":         version,
        })

    except json.JSONDecodeError:
        _send(conn, {"status": "error", "reason": "Malformed JSON"})
    except Exception as exc:
        _send(conn, {"status": "error", "reason": str(exc)})
    finally:
        conn.close()


# ── Nonce token helpers ────────────────────────────────────────────────────────
# We need the AS to remember the nonce k_i between the two protocol rounds.
# Rather than storing state server-side, we send back an encrypted token
# (AES-256-CBC under a per-node key derived from the node's share).

_NODE_TOKEN_KEYS: dict = {}   # version -> bytes(32)

def _get_token_key(version: str, x_share: int) -> bytes:
    if version not in _NODE_TOKEN_KEYS:
        raw = x_share.to_bytes((x_share.bit_length() + 7) // 8, "big")
        _NODE_TOKEN_KEYS[version] = sha256_bytes(b"nonce-token-key" + raw)
    return _NODE_TOKEN_KEYS[version]


def _encrypt_nonce(k_i: int, username: str, version: str) -> str:
    """Encrypt nonce k_i into a token so we avoid server-side state."""
    # Key = SHA256("nonce" || username || version) — simple demo key
    key = sha256_bytes(b"nonce" + username.encode() + version.encode())
    plaintext = k_i.to_bytes(64, "big") + sha256_bytes(k_i.to_bytes(64, "big"))
    return bytes_to_hex(aes256_cbc_encrypt(key, plaintext))


def _decrypt_nonce(token_hex: str, username: str, version: str):
    """Decrypt and verify nonce token. Returns k_i or None on failure."""
    if not token_hex:
        return None
    try:
        from crypto_utils import aes256_cbc_decrypt
        key = sha256_bytes(b"nonce" + username.encode() + version.encode())
        raw = aes256_cbc_decrypt(key, hex_to_bytes(token_hex))
        k_i_bytes = raw[:64]
        checksum   = raw[64:96]
        if checksum != sha256_bytes(k_i_bytes):
            return None
        return int.from_bytes(k_i_bytes, "big")
    except Exception:
        return None


def _encrypt_session_key(session_key: bytes, username: str, version: str) -> bytes:
    """Encrypt session key for transit back to client."""
    enc_key = sha256_bytes(b"session-transit" + username.encode() + version.encode())
    return aes256_cbc_encrypt(enc_key, session_key)


# ── Wire helpers ───────────────────────────────────────────────────────────────

def _send(conn: socket.socket, obj: dict):
    msg = (json.dumps(obj) + "\n").encode()
    conn.sendall(msg)


# ── Server main ────────────────────────────────────────────────────────────────

def run_server(config_path: str, malicious: bool = False):
    node = ASNode(config_path, malicious=malicious)
    host = "127.0.0.1"
    port = node.port

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    label = " [MALICIOUS]" if malicious else ""
    print(f"[AS{node.node_index}]{label} Listening on {host}:{port} …")

    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, node), daemon=True)
        t.start()


def main():
    parser = argparse.ArgumentParser(description="AS node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--malicious", action="store_true",
                        help="Run in malicious mode: return forged partial signatures")
    args = parser.parse_args()
    run_server(args.config, malicious=args.malicious)


if __name__ == "__main__":
    main()
