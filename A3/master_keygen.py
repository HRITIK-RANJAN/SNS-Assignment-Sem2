"""
master_keygen.py
================
Offline trusted-dealer setup for the Threshold Schnorr Kerberos system.

Directory layout after running:
  as_node1/
    v1/node_config.json    ← share x1 for version v1
    v2/node_config.json    ← share x1 for version v2
    node_config.json       ← active symlink / latest config (for hot-reload)
  as_node2/ ... (same)
  as_node3/ ... (same)
  tgs_node1/ ... (same)
  tgs_node2/ ... (same)
  tgs_node3/ ... (same)
  service_server/
    service_config.json    ← master pubkeys only (no private shares)
  client_data/
    client_config.json     ← node addresses + pubkeys
  params.json              ← public Schnorr parameters
  pubkeys.json             ← master public keys per version

Usage:
    python master_keygen.py [--fast]
    --fast : 128-bit q / 512-bit p for demo speed
"""

import os
import json
import argparse

from crypto_utils import (
    generate_schnorr_params,
    modpow,
    secure_random_zq,
    shamir_split,
    lagrange_coeff,
    SchnorrParams,
    int_to_hex,
)

# ── Layout constants ───────────────────────────────────────────────────────────
NODE_DIRS = {
    "as":  ["as_node1", "as_node2", "as_node3"],
    "tgs": ["tgs_node1", "tgs_node2", "tgs_node3"],
}
AS_PORTS  = [9001, 9002, 9003]
TGS_PORTS = [9011, 9012, 9013]


# ── Key generation ─────────────────────────────────────────────────────────────

def generate_key_version(params: SchnorrParams, version_id: str) -> dict:
    """
    Generate one versioned master keypair and its three Shamir shares.

    Shamir 2-of-3:  f(t) = x + a*t  (a random)
      x_i = f(i)  for i in {1, 2, 3}
      Any two shares reconstruct x = f(0) via Lagrange interpolation.
      A single share is uniformly random — reveals nothing about x.

    The master secret x is computed in memory only and never written to disk.
    """
    p, q, g = params.p, params.q, params.g

    x = secure_random_zq(q)
    y = modpow(g, x, p)

    x1, x2, x3 = shamir_split(x, q)
    shares = [(xi, modpow(g, xi, p)) for xi in (x1, x2, x3)]

    # Verify reconstruction for all three pairs
    for (i, xi), (j, xj) in [((1,x1),(2,x2)), ((1,x1),(3,x3)), ((2,x2),(3,x3))]:
        li, lj = lagrange_coeff(i, j, q)
        assert (li*xi + lj*xj) % q == x, f"Shamir check failed pair ({i},{j})"

    return {
        "version_id": version_id,
        "master_x":   x,       # only held in memory
        "master_y":   y,
        "shares":     shares,  # [(x1,y1), (x2,y2), (x3,y3)]
    }


# ── Versioned folder writers ───────────────────────────────────────────────────

def write_versioned_node_share(
    node_dir: str,
    node_type: str,
    node_index: int,
    port: int,
    params: SchnorrParams,
    version: dict,
    all_version_ids: list,
):
    """
    Write per-node config for ONE version into:
        <node_dir>/<version_id>/node_config.json

    Each versioned subfolder contains only the share for that version,
    so a node can be updated to a new version by adding a new subfolder
    and updating the top-level node_config.json symlink.
    """
    vid  = version["version_id"]
    i    = node_index - 1
    xi, yi = version["shares"][i]

    versioned_dir = os.path.join(node_dir, vid)
    os.makedirs(versioned_dir, exist_ok=True)

    cfg = {
        "node_type":    node_type,
        "node_index":   node_index,
        "port":         port,
        "version_id":   vid,
        "params": {
            "p": int_to_hex(params.p),
            "q": int_to_hex(params.q),
            "g": int_to_hex(params.g),
        },
        "key_share":    int_to_hex(xi),
        "public_share": int_to_hex(yi),
    }
    path = os.path.join(versioned_dir, "node_config.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    return path


def write_active_node_config(
    node_dir: str,
    node_type: str,
    node_index: int,
    port: int,
    params: SchnorrParams,
    versions: list,
):
    """
    Write the top-level <node_dir>/node_config.json that the running node
    process actually loads.  Contains ALL version shares so the node can
    serve any active version and perform hot-reload.

    This is what as_node.py / tgs_node.py read at startup and on RELOAD.
    """
    i = node_index - 1
    version_ids = [v["version_id"] for v in versions]

    cfg = {
        "node_type":     node_type,
        "node_index":    node_index,
        "port":          port,
        "params": {
            "p": int_to_hex(params.p),
            "q": int_to_hex(params.q),
            "g": int_to_hex(params.g),
        },
        # All version shares (keyed by version_id)
        "key_shares":    {v["version_id"]: int_to_hex(v["shares"][i][0])
                          for v in versions},
        "public_shares": {v["version_id"]: int_to_hex(v["shares"][i][1])
                          for v in versions},
        "_latest":       version_ids[-1],
        "_expired":      version_ids[:-1],
        # Pointer to versioned subfolders for auditing
        "_version_dirs": [os.path.join(node_dir, vid) for vid in version_ids],
    }
    path = os.path.join(node_dir, "node_config.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    return path


def write_service_config(
    service_dir: str,
    port: int,
    params: SchnorrParams,
    versions: list,
):
    os.makedirs(service_dir, exist_ok=True)
    version_ids = [v["version_id"] for v in versions]
    cfg = {
        "port":     port,
        "params":   {"p": int_to_hex(params.p), "q": int_to_hex(params.q),
                     "g": int_to_hex(params.g)},
        "pubkeys":  {v["version_id"]: int_to_hex(v["master_y"]) for v in versions},
        "_latest":  version_ids[-1],
        "_expired": version_ids[:-1],
    }
    path = os.path.join(service_dir, "service_config.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    return path


def write_client_config(
    client_dir: str,
    params: SchnorrParams,
    versions: list,
    as_ports: list,
    tgs_ports: list,
    service_port: int,
):
    os.makedirs(client_dir, exist_ok=True)
    version_ids = [v["version_id"] for v in versions]
    cfg = {
        "params":        {"p": int_to_hex(params.p), "q": int_to_hex(params.q),
                          "g": int_to_hex(params.g)},
        "as_nodes":      [{"index": i+1, "host": "127.0.0.1", "port": p}
                          for i, p in enumerate(as_ports)],
        "tgs_nodes":     [{"index": i+1, "host": "127.0.0.1", "port": p}
                          for i, p in enumerate(tgs_ports)],
        "service_nodes": [{"service_id": "FileService",
                           "host": "127.0.0.1", "port": service_port}],
        "pubkeys":       {v["version_id"]: int_to_hex(v["master_y"]) for v in versions},
        "_latest":       version_ids[-1],
        "_expired":      version_ids[:-1],
    }
    path = os.path.join(client_dir, "client_config.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    return path


def write_params(params: SchnorrParams, outdir: str = "."):
    data = {"p": int_to_hex(params.p), "q": int_to_hex(params.q),
            "g": int_to_hex(params.g)}
    path = os.path.join(outdir, "params.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def write_public_keys(versions: list, outdir: str = "."):
    version_ids = [v["version_id"] for v in versions]
    data = {v["version_id"]: int_to_hex(v["master_y"]) for v in versions}
    data["_latest"]  = version_ids[-1]
    data["_expired"] = version_ids[:-1]
    path = os.path.join(outdir, "pubkeys.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Threshold Kerberos master keygen")
    parser.add_argument("--fast", action="store_true",
                        help="128-bit q / 512-bit p for demo speed")
    args = parser.parse_args()

    q_bits = 128 if args.fast else 256
    p_bits = 512  if args.fast else 1024

    print("=" * 60)
    print("  Threshold Kerberos — Master Key Generation")
    print("=" * 60)

    # 1. Schnorr parameters
    print("\n[1] Generating Schnorr parameters …")
    params = SchnorrParams(*generate_schnorr_params(q_bits=q_bits, p_bits=p_bits))
    print(f"    p = {params.p.bit_length()} bits")
    print(f"    q = {params.q.bit_length()} bits")

    # 2. Two key versions
    print("\n[2] Generating key versions v1, v2 …")
    v1 = generate_key_version(params, "v1")
    v2 = generate_key_version(params, "v2")
    versions = [v1, v2]
    print(f"    v1: y = {hex(v1['master_y'])[:24]}…")
    print(f"    v2: y = {hex(v2['master_y'])[:24]}…")

    # 3. Versioned node folders
    print("\n[3] Writing versioned share folders …")
    all_vids = [v["version_id"] for v in versions]

    for node_type, dirs, ports in [("as",  NODE_DIRS["as"],  AS_PORTS),
                                    ("tgs", NODE_DIRS["tgs"], TGS_PORTS)]:
        for node_index, (node_dir, port) in enumerate(zip(dirs, ports), start=1):
            os.makedirs(node_dir, exist_ok=True)

            # One versioned subfolder per version
            for v in versions:
                vpath = write_versioned_node_share(
                    node_dir, node_type, node_index, port, params, v, all_vids
                )
                print(f"  [+] {vpath}")

            # Top-level active config (loaded by the running node process)
            apath = write_active_node_config(
                node_dir, node_type, node_index, port, params, versions
            )
            print(f"  [+] {apath}  ← active config (all versions)")

    # 4. Service + client configs
    print("\n[4] Writing service and client configs …")
    print(f"  [+] {write_service_config('service_server', 9021, params, versions)}")
    print(f"  [+] {write_client_config('client_data', params, versions, AS_PORTS, TGS_PORTS, 9021)}")

    # 5. Shared public files
    print("\n[5] Writing shared public files …")
    print(f"  [+] {write_params(params)}")
    print(f"  [+] {write_public_keys(versions)}")

    # 6. Print folder tree summary
    print("\n[6] Directory layout:")
    for node_dir in NODE_DIRS["as"] + NODE_DIRS["tgs"]:
        print(f"  {node_dir}/")
        for v in versions:
            print(f"    {v['version_id']}/node_config.json  ← x_i for {v['version_id']}")
        print(f"    node_config.json              ← active (all versions)")

    print("\n✓  Master key generation complete.")
    print("   Master secret x was NEVER written to disk.")
    print("   Each node holds only its own share xi per version.\n")


if __name__ == "__main__":
    main()
