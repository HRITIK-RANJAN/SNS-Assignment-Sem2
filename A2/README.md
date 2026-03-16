# Secure UAV Command and Control System - Implementation Guide

## 📋 Assignment Overview

**Course:** System and Network Security (CS8.403)  
**Institution:** International Institute of Information Technology, Hyderabad  
**Deadline:** February 10, 2026, 11:59 PM  
**Total Marks:** 100  
**Languages Allowed:** C, C++, or Python only

---

## 🎯 Objective

Implement a secure, distributed UAV Command-and-Control (C2) system with:
- **Mission Control Center (MCC)**: Central server managing multiple drones
- **Multiple Drones**: Client agents connecting to MCC
- **Manual ElGamal Implementation**: No high-level cryptographic libraries
- **Mutual Authentication**: Both parties verify each other
- **Session Management**: Secure per-drone session keys
- **Group Key Aggregation**: Fleet-wide secure broadcasting

**Important**: This is a **MCC-centric architecture**. Drones ONLY communicate with MCC, NOT with each other.

---

## 📁 Project Structure

```
project/
├── crypto_utils.py       # Core cryptographic primitives (MANUAL)
├── mcc.py               # Mission Control Center server
├── drone.py             # Drone client implementation
├── attacks.py           # Security attack demonstrations
├── SECURITY.md          # Security analysis (Freshness & Forward Secrecy)
├── README.md            # This file + performance logs
└── requirements.txt     # Python dependencies (minimal)
```

---

## 🔐 Cryptographic Specifications (Manual Implementation)

### Required ElGamal Primitives

All implementations must be **from scratch** in `crypto_utils.py`:

1. **Key Generation**
   - Select large prime p (SL ≥ 2048 bits) and generator g
   - Private key: x ∈ [1, p-2]
   - Public key: y = g^x (mod p)

2. **Encryption (EKU)**
   - Given message m, select random k ∈ [1, p-2]
   - Ciphertext C = (c1, c2) where:
     - c1 = g^k (mod p)
     - c2 = (m · y^k) (mod p)

3. **Decryption (DKR)**
   - m = (c2 · (c1^x)^(-1)) (mod p)

4. **Digital Signature (SignKR)**
   - Given H(m), select random k such that gcd(k, p-1) = 1
   - Signature σ = (r, s) where:
     - r = g^k (mod p)
     - s = (H(m) - x·r)·k^(-1) (mod p-1)

5. **Signature Verification (VerifyKU)**
   - Check: g^H(m) ≡ y^r · r^s (mod p)

---

## 🏗️ System Architecture & Concurrency

### MCC Server Design

The MCC must handle multiple drones simultaneously using **Multi-threading or Asynchronous I/O**:

- **Main Thread**: Listens for new connections on TCP port
- **Drone Threads**: Spawn thread per connection for Phases 0, 1, and 2
- **Fleet Registry**: Thread-safe data structure storing:
  - Drone ID
  - Socket Object
  - Session Key (SKDi,MCC)
  - Drone Public Key (for Phase 1B encryption)

### Communication Architecture

```
┌─────────────────────────────────────────────────────┐
│                Mission Control Center (MCC)          │
│  ┌──────────────────────────────────────────┐       │
│  │  Fleet Registry (Thread-Safe)            │       │
│  │  ┌────────┬────────┬────────┬──────────┐ │       │
│  │  │Drone ID│ Socket │Session │Public Key│ │       │
│  │  ├────────┼────────┼────────┼──────────┤ │       │
│  │  │  D001  │   sk1  │  SK1   │   yD1    │ │       │
│  │  │  D002  │   sk2  │  SK2   │   yD2    │ │       │
│  │  │  D003  │   sk3  │  SK3   │   yD3    │ │       │
│  │  └────────┴────────┴────────┴──────────┘ │       │
│  └──────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────┘
           ▲            ▲            ▲
           │            │            │
      TCP  │       TCP  │       TCP  │
           │            │            │
      ┌────┴───┐   ┌────┴───┐   ┌────┴───┐
      │ Drone  │   │ Drone  │   │ Drone  │
      │  D001  │   │  D002  │   │  D003  │
      └────────┘   └────────┘   └────────┘

Note: NO drone-to-drone communication
```

### MCC Command Line Interface (CLI)

Required commands:
1. **`list`** - Show all authenticated drones and their status
2. **`broadcast <cmd>`** - Generate Group Key, distribute it, send encrypted command to all drones
3. **`shutdown`** - Close all sessions and exit

---

## 📡 Protocol Phases - Detailed Specification

### Phase 0: Parameter Initialization (MCC → Drone)

**Purpose**: MCC acts as "Root of Trust" and establishes cryptographic parameters

**MCC Actions:**
1. Generate/select SL ≥ 2048
2. Generate prime p where 2^(SL-1) < p < 2^SL
3. Find generator g modulo p
4. Get current timestamp TS0
5. **Create message M0 = ⟨p ∥ g ∥ SL ∥ TS0 ∥ IDMCC⟩**
6. **CRITICAL: Sign M0 → σ0 = SignKRMCC(H(M0))**
7. Send: **OPCODE 10 ∥ M0 ∥ σ0**

**Message Format (Phase 0):**
```
┌────────┬────────┬──────┬──────┬──────┬────────┬──────────┬──────────┐
│ OPCODE │  p_len │  p   │ g_len│  g   │   SL   │   TS0    │  IDMCC   │
│   10   │ (4 B)  │ (var)│ (4 B)│ (var)│ (4 B)  │  (8 B)   │  (var)   │
└────────┴────────┴──────┴──────┴──────┴────────┴──────────┴──────────┘
┌──────────┬──────────┐
│ sig_r_len│   r      │
│  (4 B)   │  (var)   │
└──────────┴──────────┘
┌──────────┬──────────┐
│ sig_s_len│   s      │
│  (4 B)   │  (var)   │
└──────────┴──────────┘
```

**Drone Actions:**
1. Receive and parse message
2. Extract p, g, SL, TS0, IDMCC, σ0
3. **CRITICAL VALIDATION**:
   ```python
   # Check 1: Verify MCC's signature on parameters
   if not verify_signature(H(M0), σ0, KIUMCC):
       abort("Invalid MCC signature")
   
   # Check 2: Validate actual prime bit length matches claimed SL
   actual_bit_length = len(bin(p)) - 2  # Remove '0b' prefix
   if abs(actual_bit_length - SL) > 10:  # Allow ±10 bit tolerance
       abort("SL mismatch: MCC claims {SL} but p is {actual_bit_length} bits")
   
   # Check 3: Ensure minimum security level
   if SL < 2048:
       abort("Insufficient security level: {SL} < 2048")
   
   # Check 4: Verify timestamp freshness (within 5 minutes)
   if abs(current_time - TS0) > 300:
       abort("Stale parameters")
   ```
4. Store p, g, SL for use in own key generation
5. Generate drone's ElGamal keypair using p, g

**Opcode:** 10 (PARAM_INIT)

---

### Phase 1A: Drone Authentication Request (Drone → MCC)

**Purpose**: Drone initiates authentication and sends encrypted secret

**Drone Actions:**
1. Generate 256-bit random secret: KDi,MCC (this becomes basis for session key)
2. Generate random nonce: RNi (for freshness)
3. Get current timestamp: TSi
4. **Encrypt secret with MCC's public key:**
   ```
   Ci = EKUMCC(KDi,MCC) = (c1, c2)
   where c1 = g^k mod p, c2 = (KDi,MCC · yMCC^k) mod p
   ```
5. **Create authentication message:**
   ```
   M1A = ⟨TSi ∥ RNi ∥ IDDi ∥ c1 ∥ c2 ∥ yDi⟩
   Note: Include drone's public key yDi so MCC can use it in Phase 1B
   ```
6. **Sign the message:**
   ```
   σ1A = SignKRDi(H(M1A))
   ```
7. **Send: OPCODE 20 ∥ M1A ∥ σ1A**

**Message Format (Phase 1A):**
```
┌────────┬──────┬──────┬──────────┬───────────┬───────────┬──────────┐
│ OPCODE │  TSi │  RNi │   IDDi   │  c1_len   │    c1     │  c2_len  │
│   20   │ (8 B)│(32 B)│  (var)   │   (4 B)   │   (var)   │   (4 B)  │
└────────┴──────┴──────┴──────────┴───────────┴───────────┴──────────┘
┌────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│   c2   │  yDi_len │   yDi    │ sig_r_len│    r     │ sig_s_len│
│ (var)  │   (4 B)  │  (var)   │   (4 B)  │  (var)   │   (4 B)  │
└────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
┌────────┐
│   s    │
│ (var)  │
└────────┘
```

**MCC Actions:**
1. Receive and parse message
2. **Validate timestamp** (must be within 5 minutes of current time)
3. **Verify drone's signature:**
   ```python
   if not verify_signature(H(M1A), σ1A, yDi):
       send(OPCODE 60)  # ERR_MISMATCH
       abort("Invalid drone signature")
   ```
4. **Decrypt ciphertext to recover secret:**
   ```
   KDi,MCC = DKRMCC(Ci) = c2 · (c1^xMCC)^(-1) mod p
   ```
5. Store: (IDDi, Socket, KDi,MCC, yDi, RNi, TSi) in temporary registry
6. Proceed to Phase 1B

**Opcode:** 20 (AUTH_REQ)

---

### Phase 1B: MCC Authentication Response (MCC → Drone)

**Purpose**: MCC proves it successfully decrypted KDi,MCC by encrypting it back

**MCC Actions:**
1. Generate random nonce: RNMCC
2. Get current timestamp: TSMCC
3. **Encrypt THE SAME secret back using drone's public key:**
   ```
   CMCC = EKUDi(KDi,MCC) = (c1', c2')
   where c1' = g^k' mod p, c2' = (KDi,MCC · yDi^k') mod p
   ```
4. **Create response message:**
   ```
   M1B = ⟨TSMCC ∥ RNMCC ∥ IDMCC ∥ c1' ∥ c2'⟩
   ```
5. **Sign the message:**
   ```
   σ1B = SignKRMCC(H(M1B))
   ```
6. **Send: OPCODE 30 ∥ M1B ∥ σ1B**

**Message Format (Phase 1B):**
```
┌────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│ OPCODE │  TSMCC   │  RNMCC   │  IDMCC   │ c1'_len  │   c1'    │
│   30   │   (8 B)  │  (32 B)  │  (var)   │   (4 B)  │  (var)   │
└────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│ c2'_len  │   c2'    │sig_r_len │    r     │sig_s_len │    s     │
│   (4 B)  │  (var)   │   (4 B)  │  (var)   │   (4 B)  │  (var)   │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
```

**Drone Actions:**
1. Receive and parse message
2. **Validate timestamp** (must be fresh)
3. **Verify MCC's signature:**
   ```python
   if not verify_signature(H(M1B), σ1B, KUMCC):
       abort("Invalid MCC signature in Phase 1B")
   ```
4. **Decrypt ciphertext:**
   ```
   KDi,MCC_received = DKRDi(CMCC) = c2' · (c1'^xDi)^(-1) mod p
   ```
5. **Verify mutual knowledge:**
   ```python
   if KDi,MCC_received != KDi,MCC_original:
       abort("MCC failed to decrypt correctly - possible MitM")
   ```
6. Store: (RNMCC, TSMCC)
7. Proceed to Phase 2

**Opcode:** 30 (AUTH_RES)

---

### Phase 2: Session Key Derivation & Confirmation

**Purpose**: Both parties independently derive same session key and confirm via HMAC

**Both Parties Derive Session Key:**
```python
# EXACT ORDER IS CRITICAL - both must use same concatenation order
SK_Di_MCC = SHA256(KDi,MCC ∥ TSi ∥ TSMCC ∥ RNi ∥ RNMCC)

# Result is 32-byte (256-bit) session key
```

**Drone Confirmation:**
1. Get current timestamp: TSfinal (confirmation timestamp)
2. **Generate HMAC proof of session key possession:**
   ```python
   hmac_proof = HMAC-SHA256(key=SK_Di_MCC, msg=IDDi ∥ TSfinal)
   ```
3. **Send: OPCODE 40 ∥ IDDi ∥ TSfinal ∥ hmac_proof**

**Message Format (Phase 2 - SK_CONFIRM):**
```
┌────────┬──────────┬──────────┬─────────────────┐
│ OPCODE │   IDDi   │ TSfinal  │   hmac_proof    │
│   40   │  (var)   │  (8 B)   │     (32 B)      │
└────────┴──────────┴──────────┴─────────────────┘
```

**MCC Verification:**
1. Receive HMAC proof
2. Look up drone's session key from temporary registry
3. **Compute expected HMAC:**
   ```python
   expected_hmac = HMAC-SHA256(key=SK_Di_MCC, msg=IDDi ∥ TSfinal)
   ```
4. **Compare HMACs:**
   ```python
   if expected_hmac == hmac_proof:
       # Session key confirmed - authentication complete
       send(OPCODE 50)  # SUCCESS
       move_to_fleet_registry(IDDi, Socket, SK_Di_MCC, yDi)
   else:
       # HMAC mismatch - session key derivation failed
       send(OPCODE 60)  # ERR_MISMATCH
       block_drone(IDDi)  # Prevent retry attacks
   ```

**Message Format (Phase 2 - SUCCESS):**
```
┌────────┐
│ OPCODE │
│   50   │
└────────┘
```

**Message Format (Phase 2 - ERR_MISMATCH):**
```
┌────────┬─────────────────────┐
│ OPCODE │    error_message    │
│   60   │       (var)         │
└────────┴─────────────────────┘
```

**Opcodes:** 40 (SK_CONFIRM), 50 (SUCCESS), 60 (ERR_MISMATCH)

---

### Phase 3: Group Key Establishment & Broadcast

**Purpose**: Enable secure broadcast to all authenticated drones using common group key

**Trigger**: User issues `broadcast <command>` in MCC CLI

**MCC Actions:**

**Step 1: Calculate Group Key**
```python
# Aggregate all active drones' session keys
active_drones = get_authenticated_drones()  # From fleet registry
sk_list = [SK_D1, SK_D2, ..., SK_Dn]

# Include MCC's private key for additional entropy
GK = SHA256(SK_D1 ∥ SK_D2 ∥ ... ∥ SK_Dn ∥ KR_MCC)
# Result is 32-byte (256-bit) group key
```

**Step 2: Distribute Group Key to Each Drone**
For each drone Di in fleet:
```python
# Encrypt GK using drone's individual session key
encrypted_GK = AES-256-CBC(key=SK_Di_MCC, plaintext=GK, iv=random_iv)

# Send: OPCODE 70 ∥ encrypted_GK
```

**Message Format (Phase 3 - GROUP_KEY):**
```
┌────────┬─────────────────────┐
│ OPCODE │   encrypted_GK      │
│   70   │  (IV + ciphertext)  │
│        │      (48 B)         │
└────────┴─────────────────────┘
```

**Drone Actions (receiving GROUP_KEY):**
```python
# Decrypt using own session key
GK = AES-256-CBC-decrypt(key=SK_Di_MCC, ciphertext=encrypted_GK)

# Store GK for future broadcast messages
store_group_key(GK)
```

**Step 3: Send Broadcast Command**
```python
# Encrypt command with group key
encrypted_cmd = AES-256-CBC(key=GK, plaintext=command, iv=random_iv)

# Generate integrity tag
hmac_tag = HMAC-SHA256(key=GK, msg=command)

# Send to ALL drones: OPCODE 80 ∥ encrypted_cmd ∥ hmac_tag
```

**Message Format (Phase 3 - GROUP_CMD):**
```
┌────────┬─────────────────────┬──────────────┐
│ OPCODE │  encrypted_command  │   hmac_tag   │
│   80   │  (IV + ciphertext)  │    (32 B)    │
└────────┴─────────────────────┴──────────────┘
```

**Drone Actions (receiving GROUP_CMD):**
```python
# Decrypt using group key
command = AES-256-CBC-decrypt(key=GK, ciphertext=encrypted_cmd)

# Verify integrity
expected_hmac = HMAC-SHA256(key=GK, msg=command)
if expected_hmac != hmac_tag:
    abort("Integrity check failed")

# Execute command
execute_command(command)
```

**Opcodes:** 70 (GROUP_KEY), 80 (GROUP_CMD)

---

## 📋 Complete Protocol Opcode Reference

All messages MUST start with 1-byte opcode for protocol parsing:

| Opcode | Type | Direction | Description | Key Fields |
|--------|------|-----------|-------------|------------|
| **10** | PARAM_INIT | MCC → Drone | Phase 0: Crypto parameters + MCC signature | p, g, SL, TS0, IDMCC, σ0 |
| **20** | AUTH_REQ | Drone → MCC | Phase 1A: Drone authentication packet | TSi, RNi, IDDi, Ci, yDi, σ1A |
| **30** | AUTH_RES | MCC → Drone | Phase 1B: MCC proof of decryption | TSMCC, RNMCC, IDMCC, CMCC, σ1B |
| **40** | SK_CONFIRM | Drone → MCC | Phase 2: Session key verification via HMAC | IDDi, TSfinal, HMAC |
| **50** | SUCCESS | MCC → Drone | Phase 2: Authentication successful | (none) |
| **60** | ERR_MISMATCH | MCC → Drone | Phase 2: Key/HMAC verification failed | error_msg |
| **70** | GROUP_KEY | MCC → Drone | Phase 3: Encrypted group key distribution | encrypted_GK |
| **80** | GROUP_CMD | MCC → Drone | Phase 3: Encrypted broadcast command | encrypted_cmd, HMAC |
| **90** | SHUTDOWN | MCC → Drone | Server shutdown - close connection | (none) |

---

## 📚 Library Usage Policy

### ✅ Permitted Libraries

**Networking/System:**
- `socket`, `threading`, `asyncio`, `select`, `struct`, `sys`, `time`

**Hashing & MAC:**
- `hashlib` (for SHA-256 only)
- `hmac` (for HMAC-SHA256 only)

**Symmetric Encryption:**
- `pycryptodome` or `cryptography.hazmat` **ONLY for raw AES-CBC block cipher** (Phase 3)
- Usage limited to: `AES.new(key, AES.MODE_CBC, iv)`

**Randomness:**
- `secrets` or `os.urandom` (for cryptographically secure random numbers)

**Large Number Math (C/C++ only):**
- `GMP` (GNU Multiple Precision Arithmetic Library) for 2048-bit integer arithmetic
- Python students MUST use Python's built-in arbitrary-precision integers

### ❌ Strictly Not Allowed Libraries

**Using these results in ZERO marks for cryptographic portion:**

- **High-Level Security Wrappers**: `ssl`, `paramiko`, `pyOpenSSL`
- **Asymmetric Abstractions**: `Crypto.PublicKey.ElGamal`, `Crypto.PublicKey.RSA`, `cryptography.hazmat.primitives.asymmetric.*`
- **Digital Signature Modules**: `Crypto.Signature.DSS`, any pre-built signing module
- **Key Exchange Frameworks**: Any library implementing Diffie-Hellman or automated key exchange

### 🔨 The "Manual" Rule

You **MUST manually write** these functions:

1. **Modular Exponentiation**: `a^b (mod n)` using square-and-multiply
2. **Modular Inverse**: Using Extended Euclidean Algorithm
3. **ElGamal Encryption/Decryption**: Complete (c1, c2) logic
4. **ElGamal Signing/Verification**: Complete (r, s) logic

---

