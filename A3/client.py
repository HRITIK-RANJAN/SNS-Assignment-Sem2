"""
client.py
=========
Kerberos Threshold Client — orchestrates all three protocol phases.

Phase 1 (Authentication):
  1. Contact ALL 3 AS nodes SIMULTANEOUSLY (threads fan-out)
  2. Collect commitments (R_i, k_i_enc) as they arrive
  3. Stop as soon as 2 valid commitments received (first-two-valid)
  4. Verify each partial sig (R_i, s_i) against node public share y_i
  5. Combine R_global = R_i * R_j mod p,  s = s_i + s_j mod q
  6. Verify: g^s ≡ R_global * y^e mod p

Phase 2 (Service Ticket):
  Same parallel flow against TGS cluster, presenting TGT.

Phase 3 (Service Access):
  Send Service Ticket to service server.

Usage:
    python client.py --user alice --password wonderland --service FileService
"""

import json
import os
import socket
import threading
import time
import secrets
import argparse
import hashlib
import queue

from crypto_utils import (
    SchnorrParams,
    modpow,
    lagrange_coeff,
    combine_partial_sigs,
    verify_threshold_signature,
    hash_message_R,
    aes256_cbc_encrypt,
    aes256_cbc_decrypt,
    sha256_bytes,
    sha256_int,
    hex_to_int,
    int_to_hex,
    bytes_to_hex,
    hex_to_bytes,
)


# ── Config loader ──────────────────────────────────────────────────────────────

def load_config(path: str = "client_data/client_config.json") -> dict:
    with open(path) as f:
        return json.load(f)


# ── Low-level TCP helper ───────────────────────────────────────────────────────

def tcp_send_recv(host: str, port: int, obj: dict, timeout: float = 5.0) -> dict:
    """Send a JSON request and receive a JSON response over TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall((json.dumps(obj) + "\n").encode())
            data = b""
            s.settimeout(timeout)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
        return json.loads(data.decode().strip())
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return {"status": "error", "reason": f"Connection failed: {e}"}


# ── Ticket builder ─────────────────────────────────────────────────────────────

def build_ticket_payload(
    client_id: str,
    service_id: str,
    session_key_hex: str,
    lifetime_secs: int,
    version: str,
    authority: str,
) -> bytes:
    """
    Build a canonical, signed ticket payload.
    All fields included so any tampering invalidates the signature.
    """
    payload = {
        "client_id":   client_id,
        "service_id":  service_id,
        "session_key": session_key_hex,
        "issue_time":  int(time.time()),
        "lifetime":    lifetime_secs,
        "authority":   authority,
        "version":     version,
        "nonce":       bytes_to_hex(secrets.token_bytes(16)),
    }
    return json.dumps(payload, sort_keys=True).encode()


# ── Threshold signing error ────────────────────────────────────────────────────

class ThresholdSigningError(Exception):
    pass


# ── Parallel commitment round ──────────────────────────────────────────────────

def _commit_worker(node_cfg: dict, request: dict, result_queue: queue.Queue,
                   node_idx: int):
    """
    Thread worker: contact one node for a commitment.
    Puts (node_idx, response) onto result_queue when done.
    """
    resp = tcp_send_recv(node_cfg["host"], node_cfg["port"], request)
    result_queue.put((node_idx, resp))


def parallel_collect_commitments(
    nodes: list,
    make_request,          # callable(node_cfg) → dict
    threshold: int = 2,
    timeout: float = 6.0,
) -> list:
    """
    Fan out commitment requests to ALL nodes simultaneously.
    Return as soon as `threshold` valid responses arrive.
    Remaining threads continue running but their results are ignored.

    Returns list of (node_idx, response) for the first `threshold` valid ones.
    """
    result_queue = queue.Queue()

    # Launch all threads at once
    for i, node in enumerate(nodes):
        req = make_request(node)
        t = threading.Thread(target=_commit_worker,
                             args=(node, req, result_queue, i),
                             daemon=True)
        t.start()

    good = []
    deadline = time.time() + timeout

    while len(good) < threshold:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            node_idx, resp = result_queue.get(timeout=remaining)
            if resp and resp.get("status") in ("commitment", "ok") and "R_i" in resp:
                good.append((node_idx, resp))
                if len(good) == threshold:
                    break   # first-two-valid: stop waiting
        except queue.Empty:
            break

    if len(good) < threshold:
        raise ThresholdSigningError(
            f"Only {len(good)}/{len(nodes)} valid commitments received "
            f"(need {threshold})"
        )

    return good   # exactly `threshold` entries


# ── Per-node partial signature verification ────────────────────────────────────

def verify_partial(params: SchnorrParams,
                   s_i: int, R_i: int, y_i: int,
                   lam_i: int, e: int) -> bool:
    """
    Check:  g^s_i  ==  R_i · y_i^(lambda_i · e)  (mod p)

    This lets the client detect a malicious or faulty partial signature
    BEFORE combining, so a bad node can be discarded without aborting.
    """
    p = params.p; g = params.g; q = params.q
    lhs = modpow(g, s_i, p)
    rhs = (R_i * modpow(y_i, (lam_i * e) % q, p)) % p
    return lhs == rhs


# ── Signature round ────────────────────────────────────────────────────────────

def _sig_worker(node_cfg: dict, request: dict, result_queue: queue.Queue,
                node_idx: int):
    resp = tcp_send_recv(node_cfg["host"], node_cfg["port"], request)
    result_queue.put((node_idx, resp))


def parallel_collect_signatures(
    nodes: list,
    selected: list,        # [(node_idx, commit_resp), …]
    make_request,          # callable(node_cfg, R_global_hex, k_i_enc) → dict
    params: SchnorrParams,
    payload: bytes,
    R_global: int,
    pubshares: dict,       # {node_idx: y_i}
    node_indices: dict,    # {node_idx: 1-based Shamir index}
    timeout: float = 6.0,
) -> tuple:
    """
    Send R_global to the selected nodes simultaneously.
    Verify each partial sig as it arrives.
    Return (R_global, s_combined) once all selected nodes respond.
    """
    e = hash_message_R(payload, R_global)
    result_queue = queue.Queue()

    for node_idx, commit_resp in selected:
        node    = nodes[node_idx]
        k_i_enc = commit_resp.get("k_i_enc", "")
        req     = make_request(node, int_to_hex(R_global), k_i_enc)
        t = threading.Thread(target=_sig_worker,
                             args=(node, req, result_queue, node_idx),
                             daemon=True)
        t.start()

    # Collect and verify partial sigs
    partial_sigs = {}   # node_idx → s_i (only verified ones)
    deadline = time.time() + timeout

    for _ in range(len(selected)):
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        try:
            node_idx, resp = result_queue.get(timeout=remaining)
        except queue.Empty:
            break

        if not resp or resp.get("status") != "ok" or "s_i" not in resp:
            print(f"  [Client] Node {node_idx+1} sig response error: {resp}")
            continue

        s_i   = hex_to_int(resp["s_i"])
        R_i   = hex_to_int(selected[[x[0] for x in selected].index(node_idx)][1]["R_i"])
        y_i   = pubshares.get(node_idx)
        si    = node_indices[node_idx]          # 1-based Shamir index
        sj    = node_indices[[x[0] for x in selected if x[0] != node_idx][0]]

        lam_i, _ = lagrange_coeff(si, sj, params.q)

        if y_i and verify_partial(params, s_i, R_i, y_i, lam_i, e):
            partial_sigs[node_idx] = s_i
        else:
            print(f"  [Client] ✗ Node {node_idx+1} partial sig FAILED check — discarding")

    if len(partial_sigs) < 2:
        raise ThresholdSigningError(
            f"Only {len(partial_sigs)} partial sigs passed verification (need 2)"
        )

    s_list = list(partial_sigs.values())
    s_combined = s_list[0]
    for s_j in s_list[1:]:
        s_combined = combine_partial_sigs(params, s_combined, s_j)

    return R_global, s_combined


# ── Generic threshold signing orchestrator ────────────────────────────────────

def collect_threshold_signature(
    nodes: list,
    payload: bytes,
    params: SchnorrParams,
    phase1_request_fn,     # callable(node_cfg) → dict
    phase2_request_fn_factory,     # callable(selected_node_indices) → callable(node_cfg, R_global_hex, k_i_enc) → dict
    pubshares: dict,       # {node_idx: y_i int}  — for partial sig verification
    threshold: int = 2,
) -> tuple:
    """
    Full two-round parallel threshold signing.

    Round 1: Fan out to ALL nodes simultaneously; take first `threshold` valid
             commitments (first-two-valid stop).
    Round 2: Send R_global to the selected nodes simultaneously; verify each
             partial sig before combining.
    """
    # ── Round 1: parallel commitments ─────────────────────────────────────
    selected = parallel_collect_commitments(nodes, phase1_request_fn, threshold)

    # Build R_global from the selected commitments
    R_vals   = [hex_to_int(resp["R_i"]) for _, resp in selected]
    R_global = R_vals[0]
    for R_j in R_vals[1:]:
        R_global = (R_global * R_j) % params.p

    # node_indices maps array-index → 1-based Shamir index
    node_indices = {node_idx: node_idx + 1 for node_idx, _ in selected}

    # Create phase2 requests with knowledge of selected partners
    selected_node_indices = [node_idx for node_idx, _ in selected]
    phase2_request_fn = phase2_request_fn_factory(selected_node_indices)

    # ── Round 2: parallel partial signatures ──────────────────────────────
    R, s = parallel_collect_signatures(
        nodes, selected, phase2_request_fn,
        params, payload, R_global,
        pubshares, node_indices,
    )
    return R, s


# ── Phase 1: Obtain TGT ───────────────────────────────────────────────────────

def get_tgt(cfg: dict, username: str, password: str) -> dict:
    """Contact AS cluster (all 3 in parallel) → obtain TGT."""
    params   = SchnorrParams(hex_to_int(cfg["params"]["p"]),
                              hex_to_int(cfg["params"]["q"]),
                              hex_to_int(cfg["params"]["g"]))
    version  = cfg["_latest"]
    y_master = hex_to_int(cfg["pubkeys"][version])
    as_nodes = cfg["as_nodes"]

    password_hash = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()
    session_key   = secrets.token_bytes(32)
    payload = build_ticket_payload(
        client_id       = username,
        service_id      = "TGS",
        session_key_hex = bytes_to_hex(session_key),
        lifetime_secs   = 3600,
        version         = version,
        authority       = "AS-cluster",
    )

    # Load public shares for partial sig verification
    pubshares = {}
    for i, node in enumerate(as_nodes):
        node_dir = f"as_node{i+1}"
        cfg_path = os.path.join(node_dir, "node_config.json")
        if os.path.exists(cfg_path):
            d = json.load(open(cfg_path))
            pubshares[i] = hex_to_int(d["public_shares"][version])

    def phase1_req(node):
        return {
            "cmd":            "AUTH",
            "username":       username,
            "password_hash":  password_hash,
            "ticket_payload": bytes_to_hex(payload),
            "version":        version,
            "partner_index":  _infer_partner(node["index"], as_nodes),
        }

    def phase2_req_factory(selected_node_indices):
        """Create phase2 request maker with knowledge of selected partner."""
        def phase2_req(node, R_global_hex, k_i_enc):
            # Find the other selected node (our partner)
            partner_idx = None
            for idx in selected_node_indices:
                if as_nodes[idx]["index"] != node["index"]:
                    partner_idx = as_nodes[idx]["index"]
                    break
            if partner_idx is None:
                partner_idx = _infer_partner(node["index"], as_nodes)
            
            return {
                "cmd":            "AUTH",
                "username":       username,
                "password_hash":  password_hash,
                "ticket_payload": bytes_to_hex(payload),
                "version":        version,
                "partner_index":  partner_idx,
                "R_global":       R_global_hex,
                "k_i_enc":        k_i_enc,
            }
        return phase2_req

    print(f"[Client] Phase 1: contacting all {len(as_nodes)} AS nodes in parallel …")
    R, s = collect_threshold_signature(
        as_nodes, payload, params, phase1_req, phase2_req_factory, pubshares
    )

    if not verify_threshold_signature(params, y_master, payload, R, s):
        raise ThresholdSigningError("TGT local verification FAILED — aborting")
    print(f"[Client] ✓ TGT verified locally (g^s == R·y^e).")

    return {
        "payload":     bytes_to_hex(payload),
        "R":           int_to_hex(R),
        "s":           int_to_hex(s),
        "version":     version,
        "session_key": bytes_to_hex(session_key),
    }


# ── Phase 2: Obtain Service Ticket ────────────────────────────────────────────

def get_service_ticket(cfg: dict, username: str, tgt: dict, service_id: str) -> dict:
    """Present TGT to TGS cluster (all 3 in parallel) → obtain Service Ticket."""
    params    = SchnorrParams(hex_to_int(cfg["params"]["p"]),
                               hex_to_int(cfg["params"]["q"]),
                               hex_to_int(cfg["params"]["g"]))
    version   = cfg["_latest"]
    y_master  = hex_to_int(cfg["pubkeys"][version])
    tgs_nodes = cfg["tgs_nodes"]

    svc_session_key = secrets.token_bytes(32)
    st_payload = build_ticket_payload(
        client_id       = username,
        service_id      = service_id,
        session_key_hex = bytes_to_hex(svc_session_key),
        lifetime_secs   = 600,
        version         = version,
        authority       = "TGS-cluster",
    )

    pubshares = {}
    for i, node in enumerate(tgs_nodes):
        node_dir = f"tgs_node{i+1}"
        cfg_path = os.path.join(node_dir, "node_config.json")
        if os.path.exists(cfg_path):
            d = json.load(open(cfg_path))
            pubshares[i] = hex_to_int(d["public_shares"][version])

    def phase1_req(node):
        return {
            "cmd":                    "TGS",
            "username":               username,
            "tgt_payload":            tgt["payload"],
            "tgt_R":                  tgt["R"],
            "tgt_s":                  tgt["s"],
            "tgt_version":            tgt["version"],
            "service_ticket_payload": bytes_to_hex(st_payload),
            "version":                version,
            "partner_index":          _infer_partner(node["index"], tgs_nodes),
        }

    def phase2_req_factory(selected_node_indices):
        """Create phase2 request maker with knowledge of selected partner."""
        def phase2_req(node, R_global_hex, k_i_enc):
            # Find the other selected node (our partner)
            partner_idx = None
            for idx in selected_node_indices:
                if tgs_nodes[idx]["index"] != node["index"]:
                    partner_idx = tgs_nodes[idx]["index"]
                    break
            if partner_idx is None:
                partner_idx = _infer_partner(node["index"], tgs_nodes)
            
            return {
                "cmd":                    "TGS",
                "username":               username,
                "tgt_payload":            tgt["payload"],
                "tgt_R":                  tgt["R"],
                "tgt_s":                  tgt["s"],
                "tgt_version":            tgt["version"],
                "service_ticket_payload": bytes_to_hex(st_payload),
                "version":                version,
                "partner_index":          partner_idx,
                "R_global":               R_global_hex,
                "k_i_enc":                k_i_enc,
            }
        return phase2_req

    print(f"[Client] Phase 2: contacting all {len(tgs_nodes)} TGS nodes in parallel …")
    R, s = collect_threshold_signature(
        tgs_nodes, st_payload, params, phase1_req, phase2_req_factory, pubshares
    )

    if not verify_threshold_signature(params, y_master, st_payload, R, s):
        raise ThresholdSigningError("Service Ticket local verification FAILED")
    print(f"[Client] ✓ Service Ticket verified locally (g^s == R·y^e).")

    return {
        "payload":     bytes_to_hex(st_payload),
        "R":           int_to_hex(R),
        "s":           int_to_hex(s),
        "version":     version,
        "session_key": bytes_to_hex(svc_session_key),
    }


# ── Phase 3: Access service ────────────────────────────────────────────────────

def access_service(cfg: dict, service_id: str, service_ticket: dict,
                   resource: str = "hello") -> dict:
    svc_nodes = [n for n in cfg["service_nodes"] if n["service_id"] == service_id]
    if not svc_nodes:
        return {"status": "error", "reason": f"No node for '{service_id}'"}
    svc = svc_nodes[0]
    return tcp_send_recv(svc["host"], svc["port"], {
        "cmd":        "ACCESS",
        "st_payload": service_ticket["payload"],
        "st_R":       service_ticket["R"],
        "st_s":       service_ticket["s"],
        "st_version": service_ticket["version"],
        "resource":   resource,
    })


# ── Helper ─────────────────────────────────────────────────────────────────────

def _infer_partner(my_index: int, nodes: list) -> int:
    """
    Return the index of the first other node in the list.
    Used to pre-populate partner_index before we know which pair was selected.
    The node only uses partner_index to compute Lagrange coefficients;
    the client overrides with the actual selected partner in Round 2.
    """
    for node in nodes:
        if node["index"] != my_index:
            return node["index"]
    return 1


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Threshold Kerberos client")
    parser.add_argument("--user",     required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--service",  default="FileService")
    parser.add_argument("--resource", default="hello")
    parser.add_argument("--config",   default="client_data/client_config.json")
    args = parser.parse_args()

    cfg = load_config(args.config)

    try:
        tgt  = get_tgt(cfg, args.user, args.password)
        print(f"[Client] TGT obtained.            R={tgt['R'][:18]}…")

        st   = get_service_ticket(cfg, args.user, tgt, args.service)
        print(f"[Client] Service Ticket obtained. R={st['R'][:18]}…")

        resp = access_service(cfg, args.service, st, args.resource)
        print(f"[Client] Service response: {resp}")

    except ThresholdSigningError as e:
        print(f"[Client] THRESHOLD ERROR: {e}")
    except Exception as e:
        print(f"[Client] ERROR: {e}")
        raise


if __name__ == "__main__":
    main()
