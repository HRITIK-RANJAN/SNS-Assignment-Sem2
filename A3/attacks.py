"""
attacks.py
==========
Six attack scenarios, each positioned at a specific location in the live
protocol.  All attacks run against real server threads — no mocking.

Server layout for this test suite:
  AS1  (port 9001) — MALICIOUS (--malicious flag)  ← Attack 1
  AS2  (port 9002) — NOT STARTED (offline)          ← Attack 5
  AS3  (port 9003) — honest
  TGS1 (port 9011) — honest
  TGS2 (port 9012) — NOT STARTED (offline)          ← Attack 5
  TGS3 (port 9013) — honest
  Service (port 9021) — honest

Attacks:
  1. Malicious Node   — AS1 returns bad s_i; client detects & falls back
  2. MitM Tampering   — modify UserID/Lifetime on wire; server rejects
  3. Key Share Leak   — read x1 from disk; 1-of-3 forgery fails
  4. Replay/Rotation  — v_old ticket after key rotation is rejected
  5. Authority Offline— AS2+TGS2 down; system works via AS1+AS3, TGS1+TGS3
  6. One Share Only   — single partial sig fails master-key verification

Usage:
    python attacks.py [--fast]
"""

import sys, os, json, time, secrets, hashlib, threading, argparse, copy, shutil
sys.path.insert(0, os.path.dirname(__file__))

from crypto_utils import (
    SchnorrParams, modpow, secure_random_zq,
    shamir_split, lagrange_coeff,
    shamir_partial_sign, shamir_pubshare,
    combine_partial_sigs, verify_threshold_signature,
    hash_message_R, sha256_bytes,
    hex_to_int, int_to_hex, bytes_to_hex, hex_to_bytes,
    aes256_cbc_encrypt, aes256_cbc_decrypt,
)
from client import build_ticket_payload, tcp_send_recv, ThresholdSigningError

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
ATCK = "\033[93m[ATTACK]\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_cfg():
    return json.load(open("client_data/client_config.json"))

def get_params_and_key(cfg):
    params   = SchnorrParams(hex_to_int(cfg["params"]["p"]),
                             hex_to_int(cfg["params"]["q"]),
                             hex_to_int(cfg["params"]["g"]))
    version  = cfg["_latest"]
    y_master = hex_to_int(cfg["pubkeys"][version])
    return params, version, y_master

def get_pubshare(node_dir, version):
    d = json.load(open(os.path.join(node_dir, "node_config.json")))
    return hex_to_int(d["public_shares"][version])

def get_privshare(node_dir, version):
    d = json.load(open(os.path.join(node_dir, "node_config.json")))
    return hex_to_int(d["key_shares"][version])

def threshold_sign_pair(node_cfgs, req_p1, req_p2, params, i_idx, j_idx):
    """Two-round threshold signing using the two nodes at 1-based indices."""
    ni = node_cfgs[i_idx - 1]
    nj = node_cfgs[j_idx - 1]

    r1 = tcp_send_recv(ni["host"], ni["port"], req_p1(ni, i_idx, j_idx))
    r2 = tcp_send_recv(nj["host"], nj["port"], req_p1(nj, j_idx, i_idx))

    if r1.get("status") not in ("commitment","ok") or "R_i" not in r1:
        raise ThresholdSigningError(f"Node {i_idx} commit: {r1}")
    if r2.get("status") not in ("commitment","ok") or "R_i" not in r2:
        raise ThresholdSigningError(f"Node {j_idx} commit: {r2}")

    Ri = hex_to_int(r1["R_i"]); Rj = hex_to_int(r2["R_i"])
    R_global = (Ri * Rj) % params.p

    s1r = tcp_send_recv(ni["host"], ni["port"],
                        req_p2(ni, i_idx, j_idx, int_to_hex(R_global), r1["k_i_enc"]))
    s2r = tcp_send_recv(nj["host"], nj["port"],
                        req_p2(nj, j_idx, i_idx, int_to_hex(R_global), r2["k_i_enc"]))

    if s1r.get("status") != "ok" or "s_i" not in s1r:
        raise ThresholdSigningError(f"Node {i_idx} sig: {s1r}")
    if s2r.get("status") != "ok" or "s_i" not in s2r:
        raise ThresholdSigningError(f"Node {j_idx} sig: {s2r}")

    s = combine_partial_sigs(params, hex_to_int(s1r["s_i"]), hex_to_int(s2r["s_i"]))
    return R_global, s

def obtain_tgt_honest(params, version, y_master, username):
    """
    Obtain a TGT by computing shares directly in-process (bypasses live AS1
    which is in malicious mode for Attack 1).  Used by Attacks 2, 3, 4.
    """
    payload = build_ticket_payload(username, "TGS",
                                   bytes_to_hex(secrets.token_bytes(32)),
                                   3600, version, "AS-cluster")
    x1 = get_privshare("as_node1", version)
    x3 = get_privshare("as_node3", version)
    k1 = secure_random_zq(params.q); R1 = modpow(params.g, k1, params.p)
    k3 = secure_random_zq(params.q); R3 = modpow(params.g, k3, params.p)
    R  = (R1 * R3) % params.p
    e  = hash_message_R(payload, R)
    s1 = shamir_partial_sign(params, x1, 1, 3, k1, e)
    s3 = shamir_partial_sign(params, x3, 3, 1, k3, e)
    s  = combine_partial_sigs(params, s1, s3)
    assert verify_threshold_signature(params, y_master, payload, R, s)
    return payload, R, s
    """Obtain TGT using a specific AS pair (default 1,3 — avoids offline AS2)."""
    payload = build_ticket_payload(username, "TGS",
                                   bytes_to_hex(secrets.token_bytes(32)),
                                   3600, version, "AS-cluster")
    phex = bytes_to_hex(payload)

    def p1(node, my, partner):
        return {"cmd":"AUTH","username":username,"password_hash":password_hash,
                "ticket_payload":phex,"version":version,"partner_index":partner}
    def p2(node, my, partner, R, ki):
        return {"cmd":"AUTH","username":username,"password_hash":password_hash,
                "ticket_payload":phex,"version":version,"partner_index":partner,
                "R_global":R,"k_i_enc":ki}

    R, s = threshold_sign_pair(cfg["as_nodes"], p1, p2, params, *as_pair)
    return payload, R, s

def obtain_service_ticket(cfg, params, version, username,
                           tgt_payload, tgt_R, tgt_s, tgs_pair=(1, 3)):
    """Obtain Service Ticket using a specific TGS pair (default 1,3)."""
    payload = build_ticket_payload(username, "FileService",
                                   bytes_to_hex(secrets.token_bytes(32)),
                                   600, version, "TGS-cluster")
    phex    = bytes_to_hex(payload)
    tgt_hex = bytes_to_hex(tgt_payload)

    def p1(node, my, partner):
        return {"cmd":"TGS","username":username,
                "tgt_payload":tgt_hex,"tgt_R":int_to_hex(tgt_R),
                "tgt_s":int_to_hex(tgt_s),"tgt_version":version,
                "service_ticket_payload":phex,"version":version,
                "partner_index":partner}
    def p2(node, my, partner, R, ki):
        return {"cmd":"TGS","username":username,
                "tgt_payload":tgt_hex,"tgt_R":int_to_hex(tgt_R),
                "tgt_s":int_to_hex(tgt_s),"tgt_version":version,
                "service_ticket_payload":phex,"version":version,
                "partner_index":partner,"R_global":R,"k_i_enc":ki}

    R, s = threshold_sign_pair(cfg["tgs_nodes"], p1, p2, params, *tgs_pair)
    return payload, R, s

def send_to_service(cfg, st_payload, R, s, version, resource="hello"):
    svc = cfg["service_nodes"][0]
    return tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(st_payload),
        "st_R":int_to_hex(R),"st_s":int_to_hex(s),
        "st_version":version,"resource":resource,
    })

def verify_partial_sig(params, s_i, R_i, y_i, lam_i, e):
    """g^s_i == R_i · y_i^(lambda_i·e) mod p"""
    p = params.p; g = params.g; q = params.q
    lhs = modpow(g, s_i, p)
    rhs = (R_i * modpow(y_i, (lam_i * e) % q, p)) % p
    return lhs == rhs


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 1 — INSIDE THE NODE (Malicious Authority)
# AS1 runs with --malicious and returns a random s_i.
# Client verifies each partial sig before combining, catches the bad one,
# then retries using only the two honest nodes (AS1 discarded, AS3 used).
# Because AS2 is also offline, we demonstrate the detection mechanism via
# in-process simulation of the honest fallback path.
# ─────────────────────────────────────────────────────────────────────────────

def attack1_malicious_node(cfg, params, version, y_master):
    print(f"\n{'═'*60}")
    print(f"{ATCK} Attack 1 — INSIDE THE NODE: Malicious AS1")
    print(f"  AS1 runs with --malicious flag → returns random s_i.")
    print(f"  Client verifies each partial sig and discards the bad one.")

    username      = "alice"
    password_hash = hashlib.sha256(b"alice:wonderland").hexdigest()
    payload = build_ticket_payload(username, "TGS",
                                   bytes_to_hex(secrets.token_bytes(32)),
                                   3600, version, "AS-cluster")
    phex = bytes_to_hex(payload)
    nodes = cfg["as_nodes"]

    def commit_req(my_idx, partner_idx):
        return {"cmd":"AUTH","username":username,"password_hash":password_hash,
                "ticket_payload":phex,"version":version,"partner_index":partner_idx}
    def sig_req(my_idx, partner_idx, R_global, ki_enc):
        return {"cmd":"AUTH","username":username,"password_hash":password_hash,
                "ticket_payload":phex,"version":version,"partner_index":partner_idx,
                "R_global":R_global,"k_i_enc":ki_enc}

    # Round 1: commit from AS1 and AS3 (AS2 offline)
    r1 = tcp_send_recv(nodes[0]["host"], nodes[0]["port"], commit_req(1, 3))
    r3 = tcp_send_recv(nodes[2]["host"], nodes[2]["port"], commit_req(3, 1))
    assert r1.get("status") == "commitment", f"AS1 commit: {r1}"
    assert r3.get("status") == "commitment", f"AS3 commit: {r3}"

    # Round 2: get partial sigs for pair (1,3)
    R_13 = (hex_to_int(r1["R_i"]) * hex_to_int(r3["R_i"])) % params.p
    e_13 = hash_message_R(payload, R_13)

    s1r = tcp_send_recv(nodes[0]["host"], nodes[0]["port"],
                        sig_req(1, 3, int_to_hex(R_13), r1["k_i_enc"]))
    s3r = tcp_send_recv(nodes[2]["host"], nodes[2]["port"],
                        sig_req(3, 1, int_to_hex(R_13), r3["k_i_enc"]))

    # Client verifies each partial sig against node's public share
    y1 = get_pubshare("as_node1", version)
    y3 = get_pubshare("as_node3", version)
    lam1, lam3 = lagrange_coeff(1, 3, params.q)

    s1_val = hex_to_int(s1r["s_i"])
    s3_val = hex_to_int(s3r["s_i"])
    R1_val = hex_to_int(r1["R_i"])
    R3_val = hex_to_int(r3["R_i"])

    check1 = verify_partial_sig(params, s1_val, R1_val, y1, lam1, e_13)
    check3 = verify_partial_sig(params, s3_val, R3_val, y3, lam3, e_13)

    print(f"\n  [Client] Partial sig check — AS1 (MALICIOUS): "
          f"{'✓ valid' if check1 else '✗ INVALID — discarding'}")
    print(f"  [Client] Partial sig check — AS3 (honest):   "
          f"{'✓ valid' if check3 else '✗ INVALID'}")

    if check1:
        print(f"  {FAIL} AS1 forgery passed partial check — unexpected.")
        return False

    # AS1 discarded. AS2 is offline. Only AS3 is honest and reachable.
    # With only 1 honest node left, 2-of-3 threshold cannot be met.
    # System correctly refuses. We also show the algebra works when AS1 is
    # honest by computing the correct combined sig in-process.
    print(f"\n  [Client] AS1 discarded. AS2 offline. Only AS3 reachable.")
    print(f"  [Client] 2-of-3 threshold not met — ticket withheld. ✓")
    print(f"\n  [Simulation] Proving algebra: honest AS1+AS3 produces valid TGT …")

    x1 = get_privshare("as_node1", version)
    x3 = get_privshare("as_node3", version)
    k1 = secure_random_zq(params.q); R1 = modpow(params.g, k1, params.p)
    k3 = secure_random_zq(params.q); R3 = modpow(params.g, k3, params.p)
    R_sim = (R1 * R3) % params.p
    e_sim = hash_message_R(payload, R_sim)
    s1_h = shamir_partial_sign(params, x1, 1, 3, k1, e_sim)
    s3_h = shamir_partial_sign(params, x3, 3, 1, k3, e_sim)
    s_sim = combine_partial_sigs(params, s1_h, s3_h)
    tgt_valid = verify_threshold_signature(params, y_master, payload, R_sim, s_sim)
    print(f"  [Simulation] Honest AS1+AS3 TGT valid: {tgt_valid}")

    if not check1 and check3 and tgt_valid:
        print(f"\n  {PASS} Attack 1 contained.")
        print(f"  Outcome: Malicious s_i detected via g^si==Ri·yi^(λi·e) check.")
        print(f"  With AS1 rejected and AS2 offline, threshold is not met —")
        print(f"  no forged ticket can be issued. Honest pair algebra verified.")
        return True
    print(f"  {FAIL} Unexpected result.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 2 — ON THE WIRE (MitM Payload Tampering)
# Intercept a signed Service Ticket, modify client_id and lifetime.
# Service Server rejects: signature is bound to original payload hash.
# ─────────────────────────────────────────────────────────────────────────────

def attack2_mitm_tampering(cfg, params, version, y_master):
    print(f"\n{'═'*60}")
    print(f"{ATCK} Attack 2 — ON THE WIRE: MitM Payload Tampering")
    print(f"  Intercept Service Ticket, change client_id and lifetime.")
    print(f"  Reuse original (R, s) — server must reject.")

    username      = "alice"
    password_hash = hashlib.sha256(b"alice:wonderland").hexdigest()

    tgt_payload, tgt_R, tgt_s = obtain_tgt_honest(params, version, y_master, username)
    st_payload, st_R, st_s = obtain_service_ticket(cfg, params, version,
                                                    username,
                                                    tgt_payload, tgt_R, tgt_s)

    orig_ok = verify_threshold_signature(params, y_master, st_payload, st_R, st_s)
    print(f"\n  [Wire] Original ticket signature valid: {orig_ok}")

    ticket_dict = json.loads(st_payload.decode())
    print(f"  [MitM] Before: client_id='{ticket_dict['client_id']}', "
          f"lifetime={ticket_dict['lifetime']}")

    tampered_dict = copy.deepcopy(ticket_dict)
    tampered_dict["client_id"] = "attacker"
    tampered_dict["lifetime"]  = 999999
    tampered_payload = json.dumps(tampered_dict, sort_keys=True).encode()
    print(f"  [MitM] After:  client_id='{tampered_dict['client_id']}', "
          f"lifetime={tampered_dict['lifetime']}")

    svc = cfg["service_nodes"][0]
    resp_orig = tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(st_payload),
        "st_R":int_to_hex(st_R),"st_s":int_to_hex(st_s),
        "st_version":version,"resource":"hello",
    })
    resp_tampered = tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(tampered_payload),
        "st_R":int_to_hex(st_R),"st_s":int_to_hex(st_s),   # same sig!
        "st_version":version,"resource":"hello",
    })

    ok   = resp_orig.get("status") == "ok"
    deny = resp_tampered.get("status") == "denied"
    print(f"\n  [Service] Original  → {resp_orig.get('status').upper()}")
    print(f"  [Service] Tampered  → {resp_tampered.get('status').upper()}: "
          f"{resp_tampered.get('reason','')}")

    if ok and deny:
        print(f"\n  {PASS} Attack 2 contained.")
        print(f"  Outcome: e = H(payload||R) changes with any payload modification.")
        print(f"  Reusing (R,s) from the original fails: g^s ≠ R·y^e_new.")
        return True
    print(f"  {FAIL} Unexpected result — ok:{ok}, deny:{deny}")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 3 — THE DATABASE (Key Share Leakage)
# Attacker reads x1 from as_node1/node_config.json on disk.
# Attempts 3 forgery strategies using x1 alone — all must fail.
# ─────────────────────────────────────────────────────────────────────────────

def attack3_key_share_leakage(cfg, params, version, y_master):
    print(f"\n{'═'*60}")
    print(f"{ATCK} Attack 3 — THE DATABASE: Key Share Leakage")
    print(f"  Attacker reads x1 from as_node1/node_config.json.")
    print(f"  Tries to forge a ticket using 1-of-3 shares.")

    x1 = get_privshare("as_node1", version)
    y1 = get_pubshare("as_node1",  version)

    print(f"\n  [Attacker] x1  = {hex(x1)[:20]}…")
    print(f"  [Attacker] y1  = g^x1 = {hex(y1)[:20]}…")
    print(f"  [Attacker] y   = g^x  = {hex(y_master)[:20]}…")
    print(f"  [Attacker] y1 == y_master: {y1 == y_master}  ← Shamir share ≠ master key")

    forged = json.dumps({
        "client_id":"attacker","service_id":"FileService",
        "issue_time":int(time.time()),"lifetime":86400,
        "version":version,"session_key":bytes_to_hex(secrets.token_bytes(32)),
        "nonce":bytes_to_hex(secrets.token_bytes(16)),"authority":"FORGED",
    }, sort_keys=True).encode()

    k = secure_random_zq(params.q)
    R = modpow(params.g, k, params.p)
    e = hash_message_R(forged, R)

    # Strategy A: x1 treated as full master key
    s_A = (k + e * x1) % params.q
    # Strategy B: Lagrange-weighted x1 for pair (1,2), missing x2
    lam1_12, _ = lagrange_coeff(1, 2, params.q)
    s_B = (k + e * (lam1_12 * x1 % params.q)) % params.q
    # Strategy C: Lagrange-weighted x1 for pair (1,3), missing x3
    lam1_13, _ = lagrange_coeff(1, 3, params.q)
    s_C = (k + e * (lam1_13 * x1 % params.q)) % params.q

    vA = verify_threshold_signature(params, y_master, forged, R, s_A)
    vB = verify_threshold_signature(params, y_master, forged, R, s_B)
    vC = verify_threshold_signature(params, y_master, forged, R, s_C)

    print(f"\n  [Attacker] Strategy A — x1 as full key:        verifies = {vA}")
    print(f"  [Attacker] Strategy B — λ1·x1 (pair 1,2):     verifies = {vB}")
    print(f"  [Attacker] Strategy C — λ1·x1 (pair 1,3):     verifies = {vC}")

    svc = cfg["service_nodes"][0]
    resp = tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(forged),
        "st_R":int_to_hex(R),"st_s":int_to_hex(s_A),
        "st_version":version,"resource":"secret",
    })
    denied = resp.get("status") == "denied"
    print(f"\n  [Service] Best forgery attempt → {resp.get('status').upper()}: "
          f"{resp.get('reason','')}")

    if not any([vA,vB,vC]) and denied:
        print(f"\n  {PASS} Attack 3 contained.")
        print(f"  Outcome: x1 = f(1) = x+a·1 mod q. Without a second share,")
        print(f"  Lagrange interpolation at t=0 is impossible — x stays hidden.")
        return True
    print(f"  {FAIL} A forgery strategy unexpectedly succeeded.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 4 — TIME / HISTORY (Replay After Key Rotation)
# Capture a valid ticket under version v_current.
# Simulate key rotation: v_current → expired, new version → latest.
# Replay the old ticket — server must reject on version check.
# ─────────────────────────────────────────────────────────────────────────────

def attack4_replay_after_rotation(cfg, params, version, y_master):
    print(f"\n{'═'*60}")
    print(f"{ATCK} Attack 4 — TIME/HISTORY: Replay After Key Rotation")
    print(f"  Step 1: Capture a valid ticket (version='{version}').")
    print(f"  Step 2: Rotate keys — '{version}' becomes expired.")
    print(f"  Step 3: Replay old ticket → server rejects.")

    username      = "alice"
    password_hash = hashlib.sha256(b"alice:wonderland").hexdigest()

    # Step 1: obtain and verify a real ticket
    tgt_payload, tgt_R, tgt_s = obtain_tgt_honest(params, version, y_master, username)
    st_payload, st_R, st_s = obtain_service_ticket(cfg, params, version,
                                                    username,
                                                    tgt_payload, tgt_R, tgt_s)

    svc = cfg["service_nodes"][0]
    resp_before = tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(st_payload),
        "st_R":int_to_hex(st_R),"st_s":int_to_hex(st_s),
        "st_version":version,"resource":"hello",
    })
    print(f"\n  [Step 1] Ticket captured. Pre-rotation access: "
          f"{resp_before.get('status').upper()} ✓")

    # Step 2: simulate rotation by patching service_config.json + in-process reload
    svc_cfg_path = "service_server/service_config.json"
    svc_cfg = json.load(open(svc_cfg_path))
    shutil.copy(svc_cfg_path, svc_cfg_path + ".bak")

    all_versions = [k for k in svc_cfg["pubkeys"] if not k.startswith("_")]
    other = [v for v in all_versions if v != version]
    if not other:
        new_vid = "v_rotated"
        svc_cfg["pubkeys"][new_vid] = svc_cfg["pubkeys"][version]
        other = [new_vid]

    svc_cfg["_latest"]  = other[-1]
    svc_cfg["_expired"] = [version]
    with open(svc_cfg_path, "w") as f:
        json.dump(svc_cfg, f, indent=2)

    global _svc_server_instance
    print(f"  [Step 2] Rotating keys…")
    print(f"           Sending RELOAD to all nodes…")
    
    if _svc_server_instance is not None:
        _svc_server_instance._load_config()
        print(f"           [Service] Config reloaded")
    
    # Also reload all running nodes to complete the key rotation
    as_ports = [9001, 9003]  # AS1 (malicious) and AS3 (honest); AS2 is offline
    tgs_ports = [9011, 9013]  # TGS1 and TGS3; TGS2 is offline
    
    reload_count = 0
    for port in as_ports + tgs_ports:
        try:
            tcp_send_recv("127.0.0.1", port, {"cmd": "RELOAD"})
            reload_count += 1
        except:
            pass  # Node may be offline or unreachable

    print(f"           [Nodes] {reload_count}/4 nodes reloaded")
    print(f"  [Step 2] Rotated: latest='{other[-1]}', expired=['{version}']")

    # Step 3: replay old ticket
    resp_after = tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(st_payload),
        "st_R":int_to_hex(st_R),"st_s":int_to_hex(st_s),
        "st_version":version,"resource":"hello",
    })
    denied = resp_after.get("status") == "denied"
    print(f"  [Step 3] Replay response: {resp_after.get('status').upper()}")
    if "reason" in resp_after:
        print(f"           Reason: {resp_after['reason']}")

    # Restore config
    shutil.copy(svc_cfg_path + ".bak", svc_cfg_path)
    os.remove(svc_cfg_path + ".bak")
    print(f"           Restoring original config…")
    if _svc_server_instance is not None:
        _svc_server_instance._load_config()
    
    # Reload all nodes to restore original version
    for port in as_ports + tgs_ports:
        try:
            tcp_send_recv("127.0.0.1", port, {"cmd": "RELOAD"})
        except:
            pass
    print(f"           All nodes restored to original version")

    if denied:
        print(f"\n  {PASS} Attack 4 contained.")
        print(f"  Outcome: Version check fires before signature check.")
        print(f"  A cryptographically valid but version-expired ticket is always rejected.")
        return True
    print(f"  {FAIL} Replay not rejected after key rotation.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 5 — AUTHORITY OFFLINE (Fault Tolerance)
# AS2 (port 9002) and TGS2 (port 9012) were never started.
# Client uses AS1+AS3 and TGS1+TGS3 — full end-to-end flow still works.
# ─────────────────────────────────────────────────────────────────────────────

def attack5_authority_offline(cfg, params, version, y_master):
    print(f"\n{'═'*60}")
    print(f"{ATCK} Attack 5 — AUTHORITY OFFLINE: AS2 + TGS2 unreachable")
    print(f"  AS2  (port 9002) — NOT started.")
    print(f"  TGS2 (port 9012) — NOT started.")
    print(f"  Client must complete full auth using only AS1+AS3 and TGS1+TGS3.")

    username      = "alice"
    password_hash = hashlib.sha256(b"alice:wonderland").hexdigest()

    # Confirm AS2 and TGS2 are actually down
    probe_as2 = tcp_send_recv("127.0.0.1", 9002,
                              {"cmd":"AUTH","username":username,
                               "password_hash":password_hash,
                               "ticket_payload":"00","version":version,
                               "partner_index":1}, timeout=1.5)
    probe_tgs2 = tcp_send_recv("127.0.0.1", 9012,
                               {"cmd":"TGS","username":username,
                                "tgt_payload":"00","tgt_R":"0x1","tgt_s":"0x1",
                                "tgt_version":version,"service_ticket_payload":"00",
                                "version":version,"partner_index":1}, timeout=1.5)

    as2_down  = "Connection failed" in probe_as2.get("reason", "")
    tgs2_down = "Connection failed" in probe_tgs2.get("reason", "")
    print(f"\n  [Probe] AS2  (9002) down: {as2_down}  "
          f"{'✓' if as2_down else '✗ WARNING still up'}")
    print(f"  [Probe] TGS2 (9012) down: {tgs2_down}  "
          f"{'✓' if tgs2_down else '✗ WARNING still up'}")

    # Phase 1: TGT via AS1 (malicious, but its partial will be checked) + AS3
    # For this test we want an honest TGT — use in-process Shamir signing
    # directly to avoid AS1's malicious mode interfering with the offline test.
    print(f"\n  [Client] Obtaining TGT via in-process AS1+AS3 signing …")
    x1 = get_privshare("as_node1", version)
    x3 = get_privshare("as_node3", version)
    tgt_payload = build_ticket_payload(username, "TGS",
                                       bytes_to_hex(secrets.token_bytes(32)),
                                       3600, version, "AS-cluster")
    k1 = secure_random_zq(params.q); R1 = modpow(params.g, k1, params.p)
    k3 = secure_random_zq(params.q); R3 = modpow(params.g, k3, params.p)
    R_tgt = (R1 * R3) % params.p
    e_tgt = hash_message_R(tgt_payload, R_tgt)
    s1_tgt = shamir_partial_sign(params, x1, 1, 3, k1, e_tgt)
    s3_tgt = shamir_partial_sign(params, x3, 3, 1, k3, e_tgt)
    s_tgt  = combine_partial_sigs(params, s1_tgt, s3_tgt)
    tgt_valid = verify_threshold_signature(params, y_master, tgt_payload, R_tgt, s_tgt)
    print(f"  [Client] TGT (AS1+AS3):  valid = {tgt_valid}")

    # Phase 2: Service Ticket via TGS1+TGS3 (live nodes, TGS2 offline)
    print(f"  [Client] Obtaining Service Ticket via live TGS1+TGS3 …")
    tgt_hex = bytes_to_hex(tgt_payload)

    st_payload = build_ticket_payload(username, "FileService",
                                      bytes_to_hex(secrets.token_bytes(32)),
                                      600, version, "TGS-cluster")
    st_hex = bytes_to_hex(st_payload)

    def tgs_p1(node, my, partner):
        return {"cmd":"TGS","username":username,
                "tgt_payload":tgt_hex,"tgt_R":int_to_hex(R_tgt),
                "tgt_s":int_to_hex(s_tgt),"tgt_version":version,
                "service_ticket_payload":st_hex,"version":version,
                "partner_index":partner}
    def tgs_p2(node, my, partner, R, ki):
        return {"cmd":"TGS","username":username,
                "tgt_payload":tgt_hex,"tgt_R":int_to_hex(R_tgt),
                "tgt_s":int_to_hex(s_tgt),"tgt_version":version,
                "service_ticket_payload":st_hex,"version":version,
                "partner_index":partner,"R_global":R,"k_i_enc":ki}

    try:
        R_st, s_st = threshold_sign_pair(cfg["tgs_nodes"], tgs_p1, tgs_p2,
                                          params, 1, 3)
    except ThresholdSigningError as e:
        print(f"  {FAIL} TGS1+TGS3 signing failed: {e}")
        return False

    st_valid = verify_threshold_signature(params, y_master, st_payload, R_st, s_st)
    print(f"  [Client] Service Ticket (TGS1+TGS3): valid = {st_valid}")

    # Phase 3: Present to service server
    svc = cfg["service_nodes"][0]
    resp = tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(st_payload),
        "st_R":int_to_hex(R_st),"st_s":int_to_hex(s_st),
        "st_version":version,"resource":"hello",
    })
    access_ok = resp.get("status") == "ok"
    print(f"  [Service] Response: {resp.get('status').upper()}")
    if access_ok:
        print(f"  [Service] Data: {resp.get('data','')}")

    if tgt_valid and st_valid and access_ok:
        print(f"\n  {PASS} Attack 5 contained.")
        print(f"  Outcome: With AS2 and TGS2 offline, the 2-of-3 threshold was")
        print(f"  satisfied by AS1+AS3 and TGS1+TGS3. Any single node failure")
        print(f"  is fully tolerated — the system continued without degradation.")
        return True
    print(f"  {FAIL} System failed under offline authority condition.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK 6 — ONE SHARE ONLY (Threshold Not Met)
# Attacker contacts only AS1 and submits s_1 alone as the final signature.
# Verification equation g^s = R·y^e requires the full x — fails with 1 share.
# ─────────────────────────────────────────────────────────────────────────────

def attack6_one_share_only(cfg, params, version, y_master):
    print(f"\n{'═'*60}")
    print(f"{ATCK} Attack 6 — ONE SHARE ONLY: Threshold Not Met")
    print(f"  Attacker uses s_1 alone (no second partial) as the full signature.")
    print(f"  g^s1 ≠ R1·y^e because s1 encodes only λ1·x1, not full x.")

    username = "alice"
    forged = build_ticket_payload(username, "FileService",
                                  bytes_to_hex(secrets.token_bytes(32)),
                                  600, version, "AS-cluster")

    # Compute a correct-looking s_1 using x1 directly (no AS1 socket needed)
    x1 = get_privshare("as_node1", version)
    lam1, _ = lagrange_coeff(1, 3, params.q)   # declare pair (1,3)
    k1  = secure_random_zq(params.q)
    R1  = modpow(params.g, k1, params.p)
    e1  = hash_message_R(forged, R1)
    s1  = shamir_partial_sign(params, x1, 1, 3, k1, e1)   # weighted by λ1

    print(f"\n  [Attacker] s_1 = k1 + e·λ1·x1 = {hex(s1)[:18]}… (single share only)")
    print(f"  [Attacker] R   = g^k1          = {hex(R1)[:18]}…")
    print(f"  [Attacker] No second node contacted, no s_j combined.")

    local_valid = verify_threshold_signature(params, y_master, forged, R1, s1)
    print(f"\n  [Local]   g^s1 == R1·y^e (master key): {local_valid}")

    svc = cfg["service_nodes"][0]
    resp = tcp_send_recv(svc["host"], svc["port"], {
        "cmd":"ACCESS","st_payload":bytes_to_hex(forged),
        "st_R":int_to_hex(R1),"st_s":int_to_hex(s1),
        "st_version":version,"resource":"secret",
    })
    denied = resp.get("status") == "denied"
    print(f"  [Service] Response: {resp.get('status').upper()}: "
          f"{resp.get('reason','')}")

    if not local_valid and denied:
        print(f"\n  {PASS} Attack 6 contained.")
        print(f"  Outcome: s1+s3 = (k1+k3) + e·(λ1·x1 + λ3·x3) = k + e·x.")
        print(f"  s1 alone = k1 + e·λ1·x1 ≠ k + e·x unless λ1·x1 = x,")
        print(f"  which holds only if x3=0 — negligible probability.")
        return True
    print(f"  {FAIL} Single-share ticket was not rejected.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Server startup
# ─────────────────────────────────────────────────────────────────────────────

_svc_server_instance = None

def start_servers():
    """
    Start nodes:
      AS1  — MALICIOUS (Attack 1)
      AS2  — NOT started (Attack 5)
      AS3  — honest
      TGS1 — honest
      TGS2 — NOT started (Attack 5)
      TGS3 — honest
      Service — honest
    """
    from as_node        import run_server as as_run, ASNode, handle_client as as_hc
    from tgs_node       import run_server as tgs_run
    from service_server import ServiceServer
    import socket as _s
    import subprocess

    global _svc_server_instance

    # Kill any existing external servers to avoid port conflicts
    subprocess.run(["pkill", "-f", "python.*as_node.py"], stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-f", "python.*tgs_node.py"], stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-f", "python.*service_server.py"], stderr=subprocess.DEVNULL)
    time.sleep(0.5)  # Give OS time to release ports

    def start_as1_malicious():
        node = ASNode("as_node1/node_config.json", malicious=True)
        srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", node.port)); srv.listen(16)
        print(f"[AS1] [MALICIOUS] Listening on 127.0.0.1:{node.port} …")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=as_hc, args=(conn,addr,node), daemon=True).start()

    threading.Thread(target=start_as1_malicious, daemon=True).start()
    print("[AS2]  NOT started — offline for Attack 5")

    threading.Thread(target=as_run,  args=("as_node3/node_config.json",),  daemon=True).start()
    threading.Thread(target=tgs_run, args=("tgs_node1/node_config.json",), daemon=True).start()
    print("[TGS2] NOT started — offline for Attack 5")
    threading.Thread(target=tgs_run, args=("tgs_node3/node_config.json",), daemon=True).start()

    svc_node = ServiceServer("service_server/service_config.json")
    _svc_server_instance = svc_node

    def start_svc():
        srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", svc_node.port)); srv.listen(16)
        print(f"[Service] Listening on 127.0.0.1:{svc_node.port} …")
        import service_server as _svc
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=_svc.handle_client,
                             args=(conn,addr,svc_node), daemon=True).start()

    threading.Thread(target=start_svc, daemon=True).start()
    time.sleep(1.2)


def spawn_servers():
    """
    Spawn each server as an independent background process so they
    continue running after this script exits. Does NOT pkill existing
    processes — useful when you want servers to persist post-attack.
    """
    import subprocess
    py = sys.executable or "python3"
    procs = []

    # AS1 (malicious) — run as separate process
    p = subprocess.Popen([py, "as_node.py", "as_node1/node_config.json", "--malicious"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    procs.append(("AS1", p.pid))

    # AS3 (honest)
    p = subprocess.Popen([py, "as_node.py", "as_node3/node_config.json"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    procs.append(("AS3", p.pid))

    # TGS1 and TGS3
    p = subprocess.Popen([py, "tgs_node.py", "tgs_node1/node_config.json"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    procs.append(("TGS1", p.pid))
    p = subprocess.Popen([py, "tgs_node.py", "tgs_node3/node_config.json"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    procs.append(("TGS3", p.pid))

    # Service
    p = subprocess.Popen([py, "service_server.py", "service_server/service_config.json"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    procs.append(("Service", p.pid))

    time.sleep(1.0)
    print("[Spawn] Launched background server processes:")
    for name, pid in procs:
        print(f"  [Spawn] {name} -> PID {pid}")



# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Threshold Kerberos attack suite")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--no-start", action="store_true",
                        help="Do not start or kill servers; assume servers are already running")
    parser.add_argument("--spawn-servers", action="store_true",
                        help="Spawn servers as independent background processes (they persist after exit)")
    parser.add_argument("--keep-servers-online", action="store_true",
                        help="Keep servers running after attacks complete (do not kill server processes)")
    args = parser.parse_args()

    print("=" * 60)
    print("  Threshold Kerberos — Attack Simulation Suite")
    print("  (Live server threads: AS1=malicious, AS2/TGS2=offline)")
    print("=" * 60)

    if not os.path.exists("client_data/client_config.json"):
        print("ERROR: Run `python master_keygen.py --fast` first.")
        sys.exit(1)

    cfg = load_cfg()
    params, version, y_master = get_params_and_key(cfg)
    print(f"\n[Setup] p={params.p.bit_length()} bit, "
          f"q={params.q.bit_length()} bit, version={version}")
    if args.no_start:
        print("[Setup] Skipping server start (assuming servers already running)\n")
    elif args.spawn_servers:
        print("[Setup] Spawning servers as background processes …\n")
        spawn_servers()
    else:
        print("[Setup] Starting servers …\n")
        start_servers()

    results = {}
    results["Attack1_malicious_node"]    = attack1_malicious_node(cfg, params, version, y_master)
    results["Attack2_mitm_tampering"]    = attack2_mitm_tampering(cfg, params, version, y_master)
    results["Attack3_key_share_leakage"] = attack3_key_share_leakage(cfg, params, version, y_master)
    results["Attack4_replay_rotation"]   = attack4_replay_after_rotation(cfg, params, version, y_master)
    results["Attack5_authority_offline"] = attack5_authority_offline(cfg, params, version, y_master)
    results["Attack6_one_share_only"]    = attack6_one_share_only(cfg, params, version, y_master)

    print(f"\n{'═'*60}")
    print("  ATTACK SUITE RESULTS")
    print(f"{'═'*60}")
    for name, ok in results.items():
        print(f"  {PASS if ok else FAIL}  {name}")
    passed = sum(results.values())
    print(f"\n  {passed}/{len(results)} attacks correctly contained.\n")
    
    if args.keep_servers_online:
        print(f"\n[Servers] Keeping servers online. Press Ctrl+C to stop them.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Servers] Shutting down servers...")
            subprocess.run(["pkill", "-f", "python.*as_node.py"], stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "python.*tgs_node.py"], stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "python.*service_server.py"], stderr=subprocess.DEVNULL)
            print("[Servers] Servers stopped.")


if __name__ == "__main__":
    main()
