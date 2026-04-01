"""
service_server.py
=================
Service Server for the Threshold Kerberos system.

Responsibilities:
  1. Accept a Service Ticket from a client.
  2. Verify the 2-of-3 threshold Schnorr signature against the master pubkey.
  3. Check the key version — reject tickets signed with expired versions.
  4. Optionally decrypt the AES-encrypted session key embedded in the payload.
  5. Grant or deny access to the requested resource.

Wire protocol (newline-delimited JSON over TCP):
  Request:
    {"cmd": "ACCESS",
     "st_payload": "...(hex)...",
     "st_R": "0x...",
     "st_s": "0x...",
     "st_version": "v1",
     "resource": "hello"}
  Response (success):
    {"status": "ok", "message": "Access granted", "data": "..."}
  Response (failure):
    {"status": "denied", "reason": "..."}

Usage:
    python service_server.py service_server/service_config.json
"""

import os
import sys
import json
import socket
import threading
import time
import argparse

from crypto_utils import (
    SchnorrParams,
    verify_threshold_signature,
    sha256_bytes,
    hex_to_int,
    int_to_hex,
    bytes_to_hex,
    hex_to_bytes,
)


# ── Service state ──────────────────────────────────────────────────────────────

class ServiceServer:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self._load_config()

    def _load_config(self):
        with open(self.config_path) as f:
            cfg = json.load(f)
        self.port = cfg["port"]
        p = hex_to_int(cfg["params"]["p"])
        q = hex_to_int(cfg["params"]["q"])
        g = hex_to_int(cfg["params"]["g"])
        self.params  = SchnorrParams(p, q, g)
        self.pubkeys = {vid: hex_to_int(y) for vid, y in cfg["pubkeys"].items()
                        if not vid.startswith("_")}
        self.latest  = cfg["_latest"]
        self.expired = cfg.get("_expired", [])
        print(f"[Service] Config loaded. Latest key version: {self.latest}")
        print(f"[Service] Expired versions: {self.expired}")

    def is_version_valid(self, version: str) -> bool:
        return version in self.pubkeys and version not in self.expired

    def get_pubkey(self, version: str):
        return self.pubkeys.get(version)


# ── Ticket validation ──────────────────────────────────────────────────────────

def validate_ticket(server: ServiceServer, st_payload_hex: str,
                    st_R_hex: str, st_s_hex: str, st_version: str) -> tuple:
    """
    Full ticket validation pipeline:
      1. Key version check
      2. Threshold Schnorr signature verification
      3. Payload timestamp check (expiry)
      4. Parse and return ticket fields

    Returns (ok: bool, reason: str, ticket_data: dict | None)
    """
    # ── 1. Version check ───────────────────────────────────────────────────
    if not server.is_version_valid(st_version):
        return False, f"Key version '{st_version}' is expired or unknown", None

    y_master = server.get_pubkey(st_version)
    if y_master is None:
        return False, "Master public key not found for version", None

    # ── 2. Signature verification ──────────────────────────────────────────
    try:
        st_payload = hex_to_bytes(st_payload_hex)
        R = hex_to_int(st_R_hex)
        s = hex_to_int(st_s_hex)
    except (ValueError, TypeError) as e:
        return False, f"Malformed ticket fields: {e}", None

    if not verify_threshold_signature(server.params, y_master, st_payload, R, s):
        return False, "Threshold signature verification FAILED — ticket rejected", None

    # ── 3. Parse payload & check expiry ───────────────────────────────────
    try:
        ticket_data = json.loads(st_payload.decode())
    except json.JSONDecodeError:
        return False, "Ticket payload is not valid JSON", None

    issue_time = ticket_data.get("issue_time", 0)
    lifetime   = ticket_data.get("lifetime", 0)
    now        = int(time.time())

    if now > issue_time + lifetime:
        elapsed = now - issue_time
        return False, (f"Ticket expired ({elapsed}s elapsed, "
                       f"lifetime={lifetime}s)"), None

    if ticket_data.get("version") != st_version:
        return False, "Version mismatch between envelope and payload", None

    return True, "OK", ticket_data


# ── Resource handler ───────────────────────────────────────────────────────────

RESOURCE_DB = {
    "hello":    "Hello, authenticated user! Welcome to FileService.",
    "secret":   "TOP SECRET: The threshold is what stands between order and chaos.",
    "listing":  "/files: [report_q3.pdf, budget_2026.xlsx, roadmap.pptx]",
}

def handle_resource(resource: str, ticket_data: dict) -> str:
    """Return resource data after successful authentication."""
    client_id  = ticket_data.get("client_id", "?")
    service_id = ticket_data.get("service_id", "?")
    content    = RESOURCE_DB.get(resource, f"Resource '{resource}' not found")
    return f"[{service_id}] {client_id}: {content}"


# ── Connection handler ─────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr, server: ServiceServer):
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
            server._load_config()
            _send(conn, {"status": "ok", "message": "Service config reloaded"})
            return

        if cmd != "ACCESS":
            _send(conn, {"status": "error", "reason": f"Unknown command: {cmd}"})
            return

        st_payload_hex = request.get("st_payload", "")
        st_R_hex       = request.get("st_R", "")
        st_s_hex       = request.get("st_s", "")
        st_version     = request.get("st_version", server.latest)
        resource       = request.get("resource", "hello")

        ok, reason, ticket_data = validate_ticket(
            server, st_payload_hex, st_R_hex, st_s_hex, st_version
        )

        if not ok:
            print(f"[Service] DENIED from {addr}: {reason}")
            _send(conn, {"status": "denied", "reason": reason})
            return

        client_id = ticket_data.get("client_id", "?")
        print(f"[Service] GRANTED access to '{resource}' for user '{client_id}'")
        data_response = handle_resource(resource, ticket_data)
        _send(conn, {"status": "ok", "message": "Access granted", "data": data_response})

    except json.JSONDecodeError:
        _send(conn, {"status": "error", "reason": "Malformed JSON"})
    except Exception as exc:
        _send(conn, {"status": "error", "reason": str(exc)})
    finally:
        conn.close()


def _send(conn: socket.socket, obj: dict):
    conn.sendall((json.dumps(obj) + "\n").encode())


# ── Server main ────────────────────────────────────────────────────────────────

def run_server(config_path: str):
    server = ServiceServer(config_path)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", server.port))
    srv.listen(16)
    print(f"[Service] Listening on 127.0.0.1:{server.port} …")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, server),
                             daemon=True)
        t.start()


def main():
    parser = argparse.ArgumentParser(description="Service server")
    parser.add_argument("config", help="Path to service_config.json")
    args = parser.parse_args()
    run_server(args.config)


if __name__ == "__main__":
    main()
