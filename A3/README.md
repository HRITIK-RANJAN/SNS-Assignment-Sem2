# Threshold Kerberos — 2-of-3 Schnorr Signatures

A Kerberos-inspired authentication system resilient to partial authority
compromise, implemented using a 2-of-3 Threshold Schnorr Signature scheme.

## Quick Start

```bash
# 1. Install the only required dependency (AES block cipher primitive)
pip install cryptography

# 2. Generate keys (--fast uses 128/512-bit params for demo speed)
python master_keygen.py --fast

# 3. Start all authority nodes (7 terminals or background processes)
python as_node.py  as_node1/node_config.json  &
python as_node.py  as_node2/node_config.json  &
python as_node.py  as_node3/node_config.json  &
python tgs_node.py tgs_node1/node_config.json &
python tgs_node.py tgs_node2/node_config.json &
python tgs_node.py tgs_node3/node_config.json &
python service_server.py service_server/service_config.json &

# 4. Run the client
python client.py --user alice --password wonderland --service FileService

# 5. Run attack suite (in-process, no servers needed)
python attacks.py --fast
```

## File Structure

```
kerberos_threshold/
├── crypto_utils.py       # All crypto primitives (no asymmetric libs)
├── master_keygen.py      # Offline trusted-dealer key setup
├── as_node.py            # Authentication Server (3 instances)
├── tgs_node.py           # Ticket Granting Server (3 instances)
├── service_server.py     # Service verifier
├── client.py             # Full 3-phase protocol client
├── attacks.py            # Attack simulation test suite
├── README.md
├── SECURITY.md
├── params.json           # Public Schnorr parameters (generated)
├── pubkeys.json          # Master public keys per version (generated)
├── as_node{1,2,3}/       # Per-node config with private key shares
├── tgs_node{1,2,3}/      # Per-node config with private key shares
├── service_server/       # Service config (public params + pubkeys only)
└── client_data/          # Client bootstrap config
```

## Architecture

```
            ┌──────────┐   ┌──────────┐   ┌──────────┐
Client ───► │   AS1    │   │   AS2    │   │   AS3    │
            │ (x1, R1) │   │ (x2, R2) │   │ (x3, R3) │
            └──────────┘   └──────────┘   └──────────┘
                  │               │               │
                  └───────────────┴───────────────┘
                          collects ≥ 2 of 3
                          combines R = R_i*R_j
                          combines s = s_i+s_j
                          verifies g^s = R·y^e
                                   │
                             [TGT issued]
                                   │
            ┌──────────┐   ┌──────────┐   ┌──────────┐
Client ───► │  TGS1    │   │  TGS2    │   │  TGS3    │
            └──────────┘   └──────────┘   └──────────┘
                          [same flow → Service Ticket]
                                   │
                       ┌───────────────────────┐
Client ───────────────►│    Service Server      │
                       │  verify g^s = R·y^e   │
                       │  check version, expiry │
                       └───────────────────────┘
```

## Cryptographic Primitives (all manual)

| Primitive              | Implementation             |
|------------------------|----------------------------|
| Modular exponentiation | Square-and-multiply loop   |
| Modular inverse        | Extended Euclidean         |
| Primality              | Miller-Rabin (25 rounds)   |
| Hash                   | SHA-256 (hashlib)          |
| Symmetric encryption   | AES-256-CBC (manual CBC)   |
| Padding                | Manual PKCS#7              |
| Randomness             | `secrets` module (OS RNG)  |

## Ports

| Node         | Port |
|--------------|------|
| AS1          | 9001 |
| AS2          | 9002 |
| AS3          | 9003 |
| TGS1         | 9011 |
| TGS2         | 9012 |
| TGS3         | 9013 |
| ServiceServer| 9021 |

## Key Rotation

To rotate keys (increment to v2 and expire v1):

```bash
# Trigger reload on all nodes after running master_keygen.py again
echo '{"cmd":"RELOAD"}' | nc 127.0.0.1 9001
echo '{"cmd":"RELOAD"}' | nc 127.0.0.1 9011
# ... (or send RELOAD to all ports)
```

Old tickets signed under v1 will be rejected once v1 enters `_expired`.

## Test Users

| Username | Password    |
|----------|-------------|
| alice    | wonderland  |
| bob      | builder     |
| carol    | s3cr3t      |
