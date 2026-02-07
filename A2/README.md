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

## 🔧 Implementation Guide

### crypto_utils.py - Core Cryptographic Functions

```python
"""
Cryptographic Utilities for UAV C2 System
All ElGamal operations implemented manually
"""

import hashlib
import hmac
import secrets
import struct
from typing import Tuple

# ============================================================================
# HELPER FUNCTIONS - Manual Implementation Required
# ============================================================================

def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """
    Compute (base^exponent) % modulus efficiently using binary method
    
    Algorithm: Square-and-multiply (binary exponentiation)
    Time Complexity: O(log exponent)
    
    Args:
        base: Base integer
        exponent: Exponent (non-negative integer)
        modulus: Modulus
    
    Returns:
        Result of (base^exponent) % modulus
    
    Example:
        modular_exponentiation(3, 5, 7) = 5
        Because 3^5 = 243, and 243 % 7 = 5
    """
    # TODO: Implement binary square-and-multiply algorithm
    # HINT: Process exponent bit by bit from right to left
    #       For each bit: square the result
    #       If bit is 1: also multiply by base
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:  # If bit is 1
            result = (result * base) % modulus
        exponent = exponent >> 1  # Right shift (divide by 2)
        base = (base * base) % modulus  # Square the base
    
    return result


def gcd(a: int, b: int) -> int:
    """
    Compute Greatest Common Divisor using Euclidean algorithm
    
    Args:
        a, b: Integers
    
    Returns:
        GCD of a and b
    """
    # TODO: Implement Euclidean algorithm
    while b != 0:
        a, b = b, a % b
    return a


def extended_euclidean(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm
    
    Returns (gcd, x, y) such that: a*x + b*y = gcd(a, b)
    
    Args:
        a, b: Integers
    
    Returns:
        Tuple (gcd, x, y)
    
    Example:
        extended_euclidean(30, 20) = (10, 1, -1)
        Because 30*1 + 20*(-1) = 10
    """
    # TODO: Implement extended Euclidean algorithm
    if b == 0:
        return a, 1, 0
    
    gcd_val, x1, y1 = extended_euclidean(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    
    return gcd_val, x, y


def modular_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse: a^(-1) mod m
    
    Returns x such that (a * x) % m == 1
    
    Args:
        a: Integer to invert
        m: Modulus
    
    Returns:
        Modular inverse of a modulo m
    
    Raises:
        ValueError: If gcd(a, m) != 1 (inverse doesn't exist)
    
    Example:
        modular_inverse(3, 11) = 4
        Because (3 * 4) % 11 = 1
    """
    # TODO: Use extended_euclidean to compute inverse
    gcd_val, x, _ = extended_euclidean(a, m)
    
    if gcd_val != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {gcd_val} != 1")
    
    return x % m


# ============================================================================
# PRIME GENERATION - Manual Implementation Required
# ============================================================================

def is_prime_miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin Primality Test
    
    Probabilistic test with error probability ≤ 4^(-k)
    With k=40, error probability ≤ 2^(-80) (negligible)
    
    Args:
        n: Number to test for primality
        k: Number of rounds (default 40 for high confidence)
    
    Returns:
        True if n is probably prime
        False if n is definitely composite
    """
    # TODO: Implement Miller-Rabin algorithm
    # HINT:
    # 1. Handle special cases (n < 2, n == 2, even numbers)
    # 2. Write n-1 as 2^r * d (where d is odd)
    # 3. Repeat k times:
    #    - Pick random witness a in [2, n-2]
    #    - Compute x = a^d mod n
    #    - Check witness conditions
    
    # Special cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # Random in [2, n-2]
        x = modular_exponentiation(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # Composite
    
    return True  # Probably prime


def generate_large_prime(bit_length: int) -> int:
    """
    Generate a random prime number of specified bit length
    
    Args:
        bit_length: Desired bit length (e.g., 2048, 3072)
    
    Returns:
        Prime p where 2^(bit_length-1) < p < 2^bit_length
    
    Example:
        p = generate_large_prime(2048)
        # p is a random 2048-bit prime
    """
    # TODO: Implement prime generation
    # HINT:
    # 1. Generate random odd number in correct range
    # 2. Test with Miller-Rabin
    # 3. If composite, add 2 and retry
    
    while True:
        # Generate random number in range [2^(n-1), 2^n)
        p = secrets.randbits(bit_length)
        p |= (1 << (bit_length - 1))  # Set MSB to ensure bit_length bits
        p |= 1  # Set LSB to ensure odd
        
        if is_prime_miller_rabin(p):
            return p


def find_generator(p: int) -> int:
    """
    Find a primitive root (generator) modulo prime p
    
    A generator g has order p-1, meaning g^i mod p generates
    all non-zero elements in Z_p for i = 1, 2, ..., p-1
    
    Args:
        p: Prime modulus
    
    Returns:
        A generator g modulo p
    
    Note:
        This is a simplified implementation.
        For production, use known safe primes with generator 2 or 5.
    """
    # TODO: Implement generator finding
    # HINT:
    # 1. Find prime factors of p-1
    # 2. For candidate g = 2, 3, 4, ...:
    #    Check if g^((p-1)/q) != 1 mod p for all prime factors q
    #    If true, g is a generator
    
    # Simplified: Try small candidates (often works for random primes)
    # For a proper implementation, factor p-1 and verify
    for g in range(2, min(100, p)):
        if modular_exponentiation(g, p - 1, p) == 1:
            # Check if order is actually p-1 (simplified check)
            if modular_exponentiation(g, (p - 1) // 2, p) != 1:
                return g
    
    # Fallback: return 2 (often works)
    return 2


# ============================================================================
# ELGAMAL KEY GENERATION
# ============================================================================

class ElGamalKey:
    """Container for ElGamal public/private key components"""
    
    def __init__(self, p: int, g: int, x: int = None, y: int = None):
        self.p = p          # Prime modulus
        self.g = g          # Generator
        self.x = x          # Private key (secret)
        self.y = y          # Public key = g^x mod p
    
    def __repr__(self):
        return f"ElGamalKey(p={self.p}, g={self.g}, y={self.y})"


def generate_elgamal_keypair(p: int, g: int) -> Tuple[ElGamalKey, ElGamalKey]:
    """
    Generate ElGamal key pair
    
    Args:
        p: Prime modulus
        g: Generator
    
    Returns:
        Tuple (public_key, private_key)
        - public_key: ElGamalKey with (p, g, y)
        - private_key: ElGamalKey with (p, g, x, y)
    """
    # TODO: Implement key generation
    # 1. Generate random private key x in [1, p-2]
    # 2. Compute public key y = g^x mod p
    # 3. Return both key objects
    
    # Generate private key
    x = secrets.randbelow(p - 2) + 1  # Random in [1, p-2]
    
    # Compute public key
    y = modular_exponentiation(g, x, p)
    
    # Create key objects
    public_key = ElGamalKey(p=p, g=g, x=None, y=y)
    private_key = ElGamalKey(p=p, g=g, x=x, y=y)
    
    return public_key, private_key


# ============================================================================
# ELGAMAL ENCRYPTION/DECRYPTION
# ============================================================================

def elgamal_encrypt(message: int, public_key: ElGamalKey) -> Tuple[int, int]:
    """
    ElGamal Encryption
    
    Args:
        message: Integer message m (must be < p)
        public_key: ElGamalKey with (p, g, y)
    
    Returns:
        Tuple (c1, c2) where:
            c1 = g^k mod p
            c2 = (m * y^k) mod p
    
    Raises:
        ValueError: If message >= p
    """
    # TODO: Implement ElGamal encryption
    # 1. Validate message < p
    # 2. Generate random k in [1, p-2]
    # 3. Compute c1 = g^k mod p
    # 4. Compute c2 = (m * y^k) mod p
    # 5. Return (c1, c2)
    
    p, g, y = public_key.p, public_key.g, public_key.y
    
    if message >= p:
        raise ValueError(f"Message {message} must be < p ({p})")
    
    # Generate random k
    k = secrets.randbelow(p - 2) + 1
    
    # Compute ciphertext
    c1 = modular_exponentiation(g, k, p)
    c2 = (message * modular_exponentiation(y, k, p)) % p
    
    return c1, c2


def elgamal_decrypt(ciphertext: Tuple[int, int], private_key: ElGamalKey) -> int:
    """
    ElGamal Decryption
    
    Args:
        ciphertext: Tuple (c1, c2)
        private_key: ElGamalKey with (p, g, x)
    
    Returns:
        Original message m = c2 * (c1^x)^(-1) mod p
    """
    # TODO: Implement ElGamal decryption
    # 1. Unpack c1, c2 from ciphertext
    # 2. Compute s = c1^x mod p
    # 3. Compute s_inv = modular_inverse(s, p)
    # 4. Compute m = (c2 * s_inv) mod p
    # 5. Return m
    
    c1, c2 = ciphertext
    p, x = private_key.p, private_key.x
    
    # Compute shared secret
    s = modular_exponentiation(c1, x, p)
    
    # Compute inverse
    s_inv = modular_inverse(s, p)
    
    # Recover message
    m = (c2 * s_inv) % p
    
    return m


# ============================================================================
# ELGAMAL DIGITAL SIGNATURES
# ============================================================================

def elgamal_sign(message_hash: int, private_key: ElGamalKey) -> Tuple[int, int]:
    """
    ElGamal Digital Signature
    
    Args:
        message_hash: Integer hash H(m) of the message (should be < p-1)
        private_key: ElGamalKey with (p, g, x)
    
    Returns:
        Signature tuple (r, s) where:
            r = g^k mod p
            s = (H(m) - x*r) * k^(-1) mod (p-1)
    
    Note:
        k is randomly chosen such that gcd(k, p-1) = 1
    """
    # TODO: Implement ElGamal signing
    # 1. Generate random k such that gcd(k, p-1) = 1
    # 2. Compute r = g^k mod p
    # 3. Compute k_inv = modular_inverse(k, p-1)
    # 4. Compute s = ((H(m) - x*r) * k_inv) mod (p-1)
    # 5. Return (r, s)
    
    p, g, x = private_key.p, private_key.g, private_key.x
    
    # Ensure message_hash is within valid range
    message_hash = message_hash % (p - 1)
    
    # Generate k such that gcd(k, p-1) = 1
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) == 1:
            break
    
    # Compute signature
    r = modular_exponentiation(g, k, p)
    k_inv = modular_inverse(k, p - 1)
    s = ((message_hash - x * r) * k_inv) % (p - 1)
    
    return r, s


def elgamal_verify(message_hash: int, signature: Tuple[int, int], 
                   public_key: ElGamalKey) -> bool:
    """
    ElGamal Signature Verification
    
    Args:
        message_hash: Integer hash H(m)
        signature: Tuple (r, s)
        public_key: ElGamalKey with (p, g, y)
    
    Returns:
        True if signature is valid, False otherwise
    
    Verification equation: g^H(m) ≡ y^r * r^s (mod p)
    """
    # TODO: Implement ElGamal verification
    # 1. Unpack r, s from signature
    # 2. Validate r, s are in correct range
    # 3. Compute left side: g^H(m) mod p
    # 4. Compute right side: (y^r * r^s) mod p
    # 5. Return True if equal, False otherwise
    
    r, s = signature
    p, g, y = public_key.p, public_key.g, public_key.y
    
    # Validate signature components
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    
    # Ensure message_hash is within valid range
    message_hash = message_hash % (p - 1)
    
    # Compute verification equation
    lhs = modular_exponentiation(g, message_hash, p)
    rhs = (modular_exponentiation(y, r, p) * modular_exponentiation(r, s, p)) % p
    
    return lhs == rhs


# ============================================================================
# HELPER FUNCTIONS - Using Permitted Libraries
# ============================================================================

def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash
    
    Args:
        data: Bytes to hash
    
    Returns:
        32-byte hash digest
    """
    return hashlib.sha256(data).digest()


def sha256_hash_to_int(data: bytes) -> int:
    """
    Compute SHA-256 hash and convert to integer
    
    Args:
        data: Bytes to hash
    
    Returns:
        Integer representation of hash
    """
    hash_bytes = sha256_hash(data)
    return int.from_bytes(hash_bytes, 'big')


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA256
    
    Args:
        key: Secret key (bytes)
        message: Message to authenticate (bytes)
    
    Returns:
        32-byte HMAC tag
    """
    return hmac.new(key, message, hashlib.sha256).digest()


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes = None) -> bytes:
    """
    AES-256-CBC Encryption (Permitted for Phase 3 only)
    
    Args:
        key: 32-byte AES key
        plaintext: Data to encrypt
        iv: 16-byte initialization vector (generated if None)
    
    Returns:
        IV ∥ ciphertext (IV is prepended)
    """
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad
    
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    
    if iv is None:
        iv = get_random_bytes(16)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return iv + ciphertext


def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES-256-CBC Decryption (Permitted for Phase 3 only)
    
    Args:
        key: 32-byte AES key
        ciphertext: IV ∥ encrypted data
    
    Returns:
        Decrypted plaintext
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(actual_ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext


# ============================================================================
# MESSAGE SERIALIZATION HELPERS
# ============================================================================

def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes with length prefix"""
    byte_data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    length = len(byte_data)
    return struct.pack('>I', length) + byte_data


def bytes_to_int(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Parse integer from bytes with length prefix
    
    Returns: (integer_value, new_offset)
    """
    length = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    int_value = int.from_bytes(data[offset:offset+length], 'big')
    offset += length
    return int_value, offset
```

### mcc.py - Mission Control Center (Partial Implementation)

```python
"""
Mission Control Center (MCC) Server
Handles multiple drone connections with mutual authentication
"""

import socket
import threading
import time
import struct
from typing import Dict, Tuple
from crypto_utils import *

# Protocol Opcodes
OPCODE_PARAM_INIT = 10
OPCODE_AUTH_REQ = 20
OPCODE_AUTH_RES = 30
OPCODE_SK_CONFIRM = 40
OPCODE_SUCCESS = 50
OPCODE_ERR_MISMATCH = 60
OPCODE_GROUP_KEY = 70
OPCODE_GROUP_CMD = 80
OPCODE_SHUTDOWN = 90


class MissionControlCenter:
    """MCC Server - manages drone fleet"""
    
    def __init__(self, host='localhost', port=5555, security_level=2048):
        self.host = host
        self.port = port
        self.security_level = security_level
        self.id = "MCC-001"
        
        print(f"[MCC] Initializing with SL={security_level} bits...")
        
        # Generate MCC's ElGamal keys
        print(f"[MCC] Generating {security_level}-bit prime...")
        self.p = generate_large_prime(security_level)
        print(f"[MCC] Finding generator...")
        self.g = find_generator(self.p)
        print(f"[MCC] Generating ElGamal keypair...")
        self.public_key, self.private_key = generate_elgamal_keypair(self.p, self.g)
        
        print(f"[MCC] Crypto initialization complete")
        print(f"[MCC] Public key y = {self.public_key.y}")
        
        # Thread-safe fleet registry
        self.fleet_lock = threading.Lock()
        self.fleet: Dict[str, dict] = {}
        # Structure: {drone_id: {
        #   'socket': socket_object,
        #   'session_key': SK_bytes,
        #   'public_key': ElGamalKey,
        #   'address': (ip, port)
        # }}
        
        # Temporary storage for authentication in progress
        self.auth_temp_lock = threading.Lock()
        self.auth_temp: Dict[str, dict] = {}
        
        self.server_socket = None
        self.running = False
    
    def start_server(self):
        """Main server loop"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        print(f"\n[MCC] Server listening on {self.host}:{self.port}")
        print(f"[MCC] Security Level: {self.security_level} bits")
        print(f"[MCC] Ready to accept drone connections\n")
        
        # Start CLI in separate thread
        cli_thread = threading.Thread(target=self.cli_loop, daemon=True)
        cli_thread.start()
        
        # Accept connections
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                print(f"[MCC] New connection from {addr}")
                
                # Spawn handler thread
                handler = threading.Thread(
                    target=self.handle_drone,
                    args=(client_sock, addr),
                    daemon=True
                )
                handler.start()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[MCC] Error accepting connection: {e}")
        
        self.shutdown()
    
    def handle_drone(self, client_sock: socket.socket, addr: Tuple[str, int]):
        """Handle individual drone connection through all phases"""
        try:
            # Phase 0: Send parameters
            self.send_phase0(client_sock)
            
            # Phase 1A: Receive drone authentication
            drone_id, k_shared, drone_public_key, rn_drone, ts_drone = \
                self.receive_phase1a(client_sock)
            
            if not drone_id:
                print(f"[MCC] Phase 1A failed for {addr}")
                client_sock.close()
                return
            
            # Store temporary auth data
            with self.auth_temp_lock:
                self.auth_temp[drone_id] = {
                    'k_shared': k_shared,
                    'public_key': drone_public_key,
                    'rn_drone': rn_drone,
                    'ts_drone': ts_drone,
                    'socket': client_sock,
                    'address': addr
                }
            
            # Phase 1B: Send MCC authentication
            rn_mcc, ts_mcc = self.send_phase1b(client_sock, k_shared, drone_public_key)
            
            # Phase 2: Confirm session key
            if not self.confirm_session_key(client_sock, drone_id, k_shared, 
                                           ts_drone, ts_mcc, rn_drone, rn_mcc):
                print(f"[MCC] Phase 2 failed for {drone_id}")
                client_sock.close()
                return
            
            # Move to fleet registry
            with self.fleet_lock:
                with self.auth_temp_lock:
                    temp_data = self.auth_temp.pop(drone_id)
                
                # Derive session key
                sk = self.derive_session_key(k_shared, ts_drone, ts_mcc, 
                                             rn_drone, rn_mcc)
                
                self.fleet[drone_id] = {
                    'socket': client_sock,
                    'session_key': sk,
                    'public_key': drone_public_key,
                    'address': addr
                }
            
            print(f"[MCC] ✓ Drone {drone_id} authenticated successfully")
            
            # Keep connection alive
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            print(f"[MCC] Error handling drone: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                client_sock.close()
            except:
                pass
    
    def send_phase0(self, client_sock: socket.socket):
        """
        Phase 0: Parameter Initialization
        Send: OPCODE 10 ∥ p ∥ g ∥ SL ∥ TS0 ∥ IDMCC ∥ signature
        """
        # TODO: Implement Phase 0 message construction
        # 1. Get current timestamp
        # 2. Create message M0 = p ∥ g ∥ SL ∥ TS0 ∥ IDMCC
        # 3. Sign M0
        # 4. Send opcode ∥ M0 ∥ signature
        
        ts0 = int(time.time())
        
        # Build message
        msg = bytearray([OPCODE_PARAM_INIT])
        msg += int_to_bytes(self.p)
        msg += int_to_bytes(self.g)
        msg += struct.pack('>I', self.security_level)
        msg += struct.pack('>Q', ts0)
        msg += self.id.encode('utf-8')
        
        # Sign (excluding opcode)
        msg_to_sign = msg[1:]
        hash_val = sha256_hash_to_int(msg_to_sign)
        r, s = elgamal_sign(hash_val, self.private_key)
        
        msg += int_to_bytes(r)
        msg += int_to_bytes(s)
        
        # Send
        client_sock.sendall(bytes(msg))
        print(f"[MCC] Phase 0: Parameters sent")
    
    def receive_phase1a(self, client_sock: socket.socket):
        """
        Phase 1A: Drone Authentication Request
        Receive: OPCODE 20 ∥ TSi ∥ RNi ∥ IDDi ∥ Ci ∥ yDi ∥ signature
        """
        # TODO: Implement Phase 1A message parsing
        # 1. Receive and parse message
        # 2. Verify timestamp freshness
        # 3. Verify signature using drone's public key
        # 4. Decrypt ciphertext to get KDi,MCC
        # 5. Return (drone_id, KDi,MCC, drone_public_key, RNi, TSi)
        
        # Receive data (simplified - should use proper framing)
        data = client_sock.recv(8192)
        
        if not data or data[0] != OPCODE_AUTH_REQ:
            return None, None, None, None, None
        
        offset = 1
        
        # Parse timestamp
        ts_drone = struct.unpack('>Q', data[offset:offset+8])[0]
        offset += 8
        
        # Validate timestamp
        current_time = int(time.time())
        if abs(current_time - ts_drone) > 300:  # 5 minutes
            print(f"[MCC] Stale timestamp in Phase 1A")
            return None, None, None, None, None
        
        # Parse nonce
        rn_drone = data[offset:offset+32]
        offset += 32
        
        # Parse drone ID
        id_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        drone_id = data[offset:offset+id_len].decode('utf-8')
        offset += id_len
        
        # Parse ciphertext (c1, c2)
        c1, offset = bytes_to_int(data, offset)
        c2, offset = bytes_to_int(data, offset)
        
        # Parse drone's public key
        y_drone_int, offset = bytes_to_int(data, offset)
        drone_public_key = ElGamalKey(p=self.p, g=self.g, y=y_drone_int)
        
        # Parse signature
        sig_r, offset = bytes_to_int(data, offset)
        sig_s, offset = bytes_to_int(data, offset)
        
        # Verify signature
        msg_to_verify = data[1:offset - struct.unpack('>I', data[offset-struct.calcsize('>I')-sig_s.bit_length()//8-4:offset-sig_s.bit_length()//8])[0] - sig_s.bit_length()//8 - 4 - struct.unpack('>I', data[offset-struct.calcsize('>I')-sig_s.bit_length()//8-4-struct.calcsize('>I')-sig_r.bit_length()//8-4:offset-sig_s.bit_length()//8-4-sig_r.bit_length()//8])[0] - sig_r.bit_length()//8 - 4]
        
        # Simplified: hash everything before signature
        hash_val = sha256_hash_to_int(data[1:offset-16])  # Approximate
        
        if not elgamal_verify(hash_val, (sig_r, sig_s), drone_public_key):
            print(f"[MCC] Invalid signature in Phase 1A")
            return None, None, None, None, None
        
        # Decrypt ciphertext
        k_shared_int = elgamal_decrypt((c1, c2), self.private_key)
        k_shared = k_shared_int.to_bytes(32, 'big')
        
        print(f"[MCC] Phase 1A: Received auth from {drone_id}")
        return drone_id, k_shared, drone_public_key, rn_drone, ts_drone
    
    def send_phase1b(self, client_sock: socket.socket, k_shared: bytes, 
                     drone_public_key: ElGamalKey):
        """
        Phase 1B: MCC Authentication Response
        Send: OPCODE 30 ∥ TSMCC ∥ RNMCC ∥ IDMCC ∥ CMCC ∥ signature
        """
        # TODO: Implement (similar to Phase 0/1A)
        pass
    
    def confirm_session_key(self, client_sock: socket.socket, drone_id: str,
                           k_shared: bytes, ts_drone: int, ts_mcc: int,
                           rn_drone: bytes, rn_mcc: bytes) -> bool:
        """Phase 2: Session Key Confirmation via HMAC"""
        # TODO: Implement
        pass
    
    def derive_session_key(self, k_shared: bytes, ts_drone: int, ts_mcc: int,
                          rn_drone: bytes, rn_mcc: bytes) -> bytes:
        """
        Derive session key: SK = H(KDi,MCC ∥ TSi ∥ TSMCC ∥ RNi ∥ RNMCC)
        """
        data = k_shared
        data += struct.pack('>Q', ts_drone)
        data += struct.pack('>Q', ts_mcc)
        data += rn_drone
        data += rn_mcc
        
        return sha256_hash(data)
    
    def cli_loop(self):
        """Command Line Interface"""
        print("\n" + "="*50)
        print("MCC Command Line Interface")
        print("Commands: list, broadcast <cmd>, shutdown")
        print("="*50 + "\n")
        
        while self.running:
            try:
                cmd = input("MCC> ").strip()
                
                if cmd == "list":
                    self.cmd_list()
                elif cmd.startswith("broadcast "):
                    command = cmd[10:]
                    self.cmd_broadcast(command)
                elif cmd == "shutdown":
                    self.cmd_shutdown()
                    break
                else:
                    print("Unknown command. Available: list, broadcast <cmd>, shutdown")
            except (EOFError, KeyboardInterrupt):
                break
    
    def cmd_list(self):
        """Show all authenticated drones"""
        with self.fleet_lock:
            if not self.fleet:
                print("No drones connected")
            else:
                print(f"\nConnected drones: {len(self.fleet)}")
                print("-" * 60)
                for drone_id, info in self.fleet.items():
                    print(f"  {drone_id:15s} @ {info['address'][0]}:{info['address'][1]}")
                print("-" * 60)
    
    def cmd_broadcast(self, command: str):
        """Phase 3: Group Key Distribution and Broadcast"""
        with self.fleet_lock:
            if not self.fleet:
                print("No drones to broadcast to")
                return
            
            print(f"\n[MCC] Broadcasting command: '{command}'")
            
            # Step 1: Calculate Group Key
            sk_list = [info['session_key'] for info in self.fleet.values()]
            gk = self.calculate_group_key(sk_list)
            print(f"[MCC] Group key generated")
            
            # Step 2: Distribute GK to each drone
            for drone_id, info in self.fleet.items():
                try:
                    # Encrypt GK with drone's session key
                    encrypted_gk = aes_cbc_encrypt(info['session_key'], gk)
                    
                    # Send OPCODE 70 ∥ encrypted_GK
                    msg = bytes([OPCODE_GROUP_KEY]) + encrypted_gk
                    info['socket'].sendall(msg)
                    
                except Exception as e:
                    print(f"[MCC] Failed to send GK to {drone_id}: {e}")
            
            print(f"[MCC] Group key distributed to {len(self.fleet)} drones")
            
            # Step 3: Send encrypted command
            cmd_bytes = command.encode('utf-8')
            encrypted_cmd = aes_cbc_encrypt(gk, cmd_bytes)
            hmac_tag = hmac_sha256(gk, cmd_bytes)
            
            msg = bytes([OPCODE_GROUP_CMD]) + encrypted_cmd + hmac_tag
            
            for drone_id, info in self.fleet.items():
                try:
                    info['socket'].sendall(msg)
                except Exception as e:
                    print(f"[MCC] Failed to send command to {drone_id}: {e}")
            
            print(f"[MCC] ✓ Broadcast complete\n")
    
    def calculate_group_key(self, session_keys: list) -> bytes:
        """
        Calculate Group Key: GK = H(SKD1 ∥ SKD2 ∥ ... ∥ SKDn ∥ KRMCC)
        """
        data = b''.join(session_keys)
        # Add MCC's private key for additional entropy
        data += int_to_bytes(self.private_key.x)
        
        return sha256_hash(data)
    
    def cmd_shutdown(self):
        """Shutdown all connections"""
        print("\n[MCC] Shutting down...")
        
        with self.fleet_lock:
            for drone_id, info in self.fleet.items():
                try:
                    # Send shutdown opcode
                    info['socket'].sendall(bytes([OPCODE_SHUTDOWN]))
                    info['socket'].close()
                except:
                    pass
        
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        print("[MCC] Shutdown complete")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='UAV Mission Control Center')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=5555, help='Server port')
    parser.add_argument('--security-level', type=int, default=2048,
                       choices=[2048, 3072], help='Security level (bits)')
    args = parser.parse_args()
    
    mcc = MissionControlCenter(args.host, args.port, args.security_level)
    mcc.start_server()
```

---

## 📝 Required Deliverables

### 1. Code Files (Must Submit)

- [x] **crypto_utils.py**
  - All manual ElGamal primitives
  - Modular arithmetic functions
  - AES/HMAC wrappers

- [x] **mcc.py**
  - Concurrent server with threading
  - CLI with list/broadcast/shutdown commands
  - All protocol phases implemented

- [x] **drone.py**
  - Client protocol logic
  - All phases (0, 1A, 1B, 2, 3)
  - Command reception and execution

- [x] **attacks.py**
  - Replay Attack demonstration
  - MitM Tampering demonstration
  - Unauthorized Access demonstration

### 2. Documentation Files (Must Submit)

- [x] **SECURITY.md** - Explain:
  - **Freshness**: How timestamps and nonces prevent replay attacks
  - **Forward Secrecy**: How session keys protect past communications

- [x] **README.md** - Include:
  - Performance logs template (filled with actual results)
  - Modular exponentiation time for 2048-bit primes
  - Prime generation benchmarks
  - Full protocol execution time per drone

### 3. Dependencies (Must Submit)

- [x] **requirements.txt**
  ```
  pycryptodome==3.19.0
  ```

---

## 📊 Performance Benchmarks Template

After implementation, fill in this template in your README:

```
=== Cryptographic Performance Benchmarks ===
Hardware: [Your CPU model]
Security Level: 2048 bits

Prime Generation:
- Average time: ___ seconds
- Min time: ___ seconds
- Max time: ___ seconds
- Trials: 10

Modular Exponentiation (2048-bit):
- Average time: ___ ms
- Trials: 100

ElGamal Operations:
- Encryption time: ___ ms
- Decryption time: ___ ms
- Signing time: ___ ms
- Verification time: ___ ms

Full Protocol Execution (single drone):
- Phase 0 (Parameter Init): ___ ms
- Phase 1A (Drone Auth): ___ ms
- Phase 1B (MCC Auth): ___ ms
- Phase 2 (SK Confirm): ___ ms
- Total authentication time: ___ ms

Group Key Operations (n=10 drones):
- GK calculation time: ___ ms
- GK distribution time: ___ ms
- Broadcast command time: ___ ms

Memory Usage:
- Per drone connection: ___ MB
- Total for 10 drones: ___ MB
```

---

## 🚀 Quick Start Guide

### Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Run MCC Server

```bash
python mcc.py --host localhost --port 5555 --security-level 2048
```

### Run Drones (separate terminals)

```bash
# Terminal 2
python drone.py --id D001 --mcc-host localhost --mcc-port 5555

# Terminal 3
python drone.py --id D002 --mcc-host localhost --mcc-port 5555

# Terminal 4
python drone.py --id D003 --mcc-host localhost --mcc-port 5555
```

### Use MCC CLI

```
MCC> list
Connected drones: 3
------------------------------------------------------------
  D001            @ 127.0.0.1:54321
  D002            @ 127.0.0.1:54322
  D003            @ 127.0.0.1:54323
------------------------------------------------------------

MCC> broadcast RETURN_TO_BASE
[MCC] Broadcasting command: 'RETURN_TO_BASE'
[MCC] Group key generated
[MCC] Group key distributed to 3 drones
[MCC] ✓ Broadcast complete

MCC> shutdown
[MCC] Shutting down...
[MCC] Shutdown complete
```

### Run Attack Demonstrations

```bash
python attacks.py
```

---

## 🎯 Grading Rubric

| Component | Points | Criteria |
|-----------|--------|----------|
| **Cryptographic Implementation** | **40** | |
| - Modular arithmetic (exp, inverse) | 8 | Correct & efficient (binary method) |
| - ElGamal encryption/decryption | 10 | Functional with correct (c1, c2) logic |
| - ElGamal signatures | 12 | Functional sign/verify with (r, s) |
| - Prime generation | 10 | 2048-bit primes in reasonable time (<2 min) |
| **Protocol Implementation** | **35** | |
| - Phase 0 (Parameters) | 5 | Correct distribution with MCC signature & drone validation |
| - Phase 1 (Mutual Auth) | 10 | Both parties authenticate with signature verification |
| - Phase 2 (Session Key) | 10 | Correct SK derivation & HMAC confirmation |
| - Phase 3 (Group Key) | 10 | GK aggregation and broadcast functional |
| **Concurrency** | **10** | |
| - Multi-threading | 5 | Multiple drones connect simultaneously |
| - Thread safety | 5 | No race conditions in fleet registry |
| **Security** | **10** | |
| - Attack demonstrations | 5 | All three attacks work and show vulnerabilities |
| - SECURITY.md | 5 | Clear explanations of freshness & forward secrecy |
| **Documentation** | **5** | |
| - Code comments | 2 | All complex functions documented |
| - README.md benchmarks | 3 | Complete performance logs filled in |

**Total: 100 points**

---

## ✅ Success Criteria

Before submission, verify:

- [ ] All cryptographic functions manually implemented (no forbidden libraries)
- [ ] MCC server handles ≥3 concurrent drone connections
- [ ] All protocol phases execute successfully with correct message formats
- [ ] Group key distribution works for fleet broadcast
- [ ] All three attacks demonstrate protocol vulnerabilities
- [ ] 2048-bit operations complete in reasonable time (<5 sec per operation)
- [ ] SECURITY.md explains freshness (timestamps/nonces) and forward secrecy
- [ ] README.md performance benchmarks filled with actual measurements
- [ ] Code is well-documented with comments

---

## 🔒 Critical Implementation Notes

### 1. Phase 0 Validation (CRITICAL)
Drone MUST verify:
```python
# Check 1: Verify MCC's signature on parameters
if not verify_signature(H(M0), σ0, KU_MCC):
    abort("Invalid MCC signature")

# Check 2: Actual prime bit length matches claimed SL
actual_bits = len(bin(p)) - 2
if abs(actual_bits - SL) > 10:  # Allow ±10 bit tolerance
    abort(f"SL mismatch: claimed {SL}, actual {actual_bits}")

# Check 3: Minimum security level
if SL < 2048:
    abort(f"Insufficient security: {SL} < 2048")
```

### 2. Session Key Derivation (CRITICAL)
Exact concatenation order:
```python
SK = SHA256(KDi,MCC ∥ TSi ∥ TSMCC ∥ RNi ∥ RNMCC)
```

### 3. Group Key Aggregation (CRITICAL)
Include MCC's private key:
```python
GK = SHA256(SKD1 ∥ SKD2 ∥ ... ∥ SKDn ∥ KR_MCC)
```

### 4. Timestamp Validation (CRITICAL)
Reject messages with timestamps:
- More than 5 minutes old
- In the future
- Duplicates (replay detection)

### 5. Communication Architecture
- Drones ONLY communicate with MCC
- NO drone-to-drone communication
- All broadcasts go through MCC

---

**Last Updated:** February 7, 2026

**Good luck with your implementation! 🚁🔐**