# 🚀 Quick Start Guide - Secure UAV C2 System

**Complete guide to installation, running, and testing the Secure UAV Command-and-Control System**

---

## 📚 Table of Contents

1. [Installation](#installation)
2. [Running the System](#running-the-system)
3. [Understanding the Code Files](#understanding-the-code-files)
4. [Security Attack Demonstrations](#security-attack-demonstrations)
5. [Command Reference](#command-reference)
6. [Troubleshooting](#troubleshooting)
7. [Advanced Usage](#advanced-usage)

---

## 📦 Installation

### 1. Install Dependencies

```bash
cd /home/learning/Desktop/SEM2/SNS/ASSIGNMENTS/A2
pip install -r requirements.txt
```

**Required Package:**
- `pycryptodome==3.19.0` (for AES-256 CBC mode only)

### 2. Verify Installation

```bash
python3 crypto_utils.py
```

**Expected output:**
```
Running crypto utility tests...
✓ Modular exponentiation tests passed
✓ Modular inverse tests passed
✓ ElGamal tests passed
✓ AES tests passed
✓ Hash and HMAC tests passed

✓ All crypto tests passed!
```

---

## 🎯 Running the System

### Basic 3-Terminal Setup

#### Terminal 1: Start MCC Server

```bash
python3 mcc.py --host localhost --port 5555 --security-level 2048
```

**Output:**
```
[MCC] Initializing with security level 2048...
[MCC] Generating large prime (2048 bits)...
[MCC] Prime generated: 2048 bits
[MCC] Finding generator...
[MCC] Generator found: 2
[MCC] Generating MCC key pair...
[MCC] MCC Public Key Y: 1234567890...
[MCC] Initialized successfully
[MCC] Server listening on localhost:5555
[MCC] Command Interface Ready
Commands: list | broadcast <cmd> | shutdown | status
MCC> 
```

**Key Points:**
- MCC generates cryptographic parameters (p, g) at startup
- Creates its own ElGamal keypair (x, y)
- Starts listening on specified port (default: 5555)
- Ready to accept drone connections

#### Terminal 2: Start Drone 1

```bash
python3 drone.py --id D001 --mcc-host localhost --mcc-port 5555
```

**Output:**
```
[D001] Initialized
[D001] Connected to MCC at localhost:5555
[D001] Phase 0: Received parameters
[D001]   - Prime: 2048 bits
[D001]   - Generator: 2
[D001]   - Security Level: 2048
[D001] Generating own key pair...
[D001] Key pair generated
[D001]   - Public Key: 9876543210...
[D001] Phase 1A: Sent authentication request
[D001] Phase 1B: Received MCC response
[D001] Phase 2: Sent session key confirmation
[D001] Authentication successful!
[D001]   Session Key: a1b2c3d4e5f6...
[D001] Entering listening mode...
```

**Key Points:**
- Drone receives cryptographic parameters from MCC
- Generates its own ElGamal keypair
- Completes mutual authentication (Phase 1A, 1B)
- Derives unique session key (Phase 2)
- Enters listening mode for commands

#### Terminal 3: Start Drone 2 (Optional)

```bash
python3 drone.py --id D002 --mcc-host localhost --mcc-port 5555
```

**Same authentication flow as D001**

#### Terminal 1 (MCC): Execute Commands

**List connected drones:**
```
MCC> list
```

**Output:**
```
======================================================================
Active Drones:
----------------------------------------------------------------------
Drone ID             | Address               | Status         
----------------------------------------------------------------------
D001                 | ('localhost', 54321)  | Authenticated  
D002                 | ('localhost', 54322)  | Authenticated  
----------------------------------------------------------------------
Total: 2 drone(s)
======================================================================
```

**Broadcast a command:**
```
MCC> broadcast RETURN_TO_BASE
```

**Output:**
```
[MCC] Broadcasting command: RETURN_TO_BASE
[MCC] Generated Group Key: a1b2c3d4e5f6...
[MCC] Sent GK to D001
[MCC] Sent GK to D002
[MCC] Broadcast to D001
[MCC] Broadcast to D002
```

**Drone Terminals: Receive Commands**
```
[D001] Received Group Key: a1b2c3d4e5f6...
[D001] Received command: RETURN_TO_BASE
[D001] >> Executing: Returning to base...
[D002] Received Group Key: a1b2c3d4e5f6...
[D002] Received command: RETURN_TO_BASE
[D002] >> Executing: Returning to base...
```

**Shutdown:**
```
MCC> shutdown
[MCC] Initiating shutdown...
```

---

## 📂 Understanding the Code Files

### Core Files Overview

| File | Lines | Purpose | Key Features |
|------|-------|---------|--------------|
| **crypto_utils.py** | 757 | Cryptographic primitives | Manual ElGamal, AES-256, SHA-256, HMAC |
| **mcc.py** | ~750 | Mission Control Center | Multi-threaded server, authentication, broadcasting |
| **drone.py** | ~700 | UAV Drone client | Connection, authentication, command execution |
| **attacks.py** | 572 | Security demonstrations | 5 attack scenarios with defenses |
| **requirements.txt** | 1 | Dependencies | pycryptodome==3.19.0 |

### File 1: crypto_utils.py

**Purpose:** Core cryptographic library with manual ElGamal implementation

**Key Functions:**

```python
# Mathematical Foundations
modular_exponentiation(base, exp, mod)  # Fast modular exponentiation
modular_inverse(a, m)                   # Compute multiplicative inverse
extended_euclidean(a, b)                # Extended GCD algorithm
gcd(a, b)                               # Greatest common divisor

# Prime Generation
generate_large_prime(bit_length)        # Generate 2048-bit primes
is_prime_miller_rabin(n, k=40)         # Probabilistic primality test
find_generator(p)                       # Find primitive root mod p

# ElGamal Cryptography
generate_elgamal_keypair(p, g)         # Generate (x, y) keypair
elgamal_encrypt(message, public_key)   # Encrypt: (c1, c2)
elgamal_decrypt(ciphertext, private_key) # Decrypt: m
elgamal_sign(hash, private_key)        # Sign: (r, s)
elgamal_verify(hash, sig, public_key)  # Verify signature

# Symmetric Cryptography
aes_encrypt(key, plaintext)            # AES-256-CBC encryption
aes_decrypt(key, iv, ciphertext)       # AES-256-CBC decryption

# Hashing & MAC
hash_sha256(data)                       # SHA-256 hash
hash_sha256_int(data)                   # SHA-256 as integer
hmac_sha256(key, data)                  # HMAC-SHA256

# Utility Functions
bytes_to_int(data)                      # Convert bytes to integer
int_to_bytes(n, length)                 # Convert integer to bytes
serialize_key(key)                      # Serialize ElGamal key
deserialize_key(data)                   # Deserialize ElGamal key
```

**Test Suite:**
```bash
python3 crypto_utils.py
# Runs comprehensive tests on all cryptographic functions
```

### File 2: mcc.py

**Purpose:** Mission Control Center - central server managing UAV fleet

**Key Components:**

1. **Server Initialization**
   - Generates cryptographic parameters (p, g)
   - Creates MCC ElGamal keypair
   - Starts TCP server on port 5555

2. **Phase 0: Parameter Distribution**
   - Sends (p, g, y_MCC, SL) to connecting drones
   - Includes digital signature for authenticity
   - Prevents tampering with parameters

3. **Phase 1A: Drone Authentication Request**
   - Receives drone's authentication message
   - Validates timestamp (30-second window)
   - Verifies digital signature
   - Decrypts shared secret

4. **Phase 1B: MCC Response**
   - Sends authentication response
   - Includes shared secret + nonce
   - Digitally signed by MCC

5. **Phase 2: Session Key Confirmation**
   - Derives session key: SK = SHA256(shared_secret || timestamps || nonces)
   - Verifies HMAC confirmation from drone
   - Session established

6. **Phase 3: Group Key Broadcasting**
   - Generates random group key for fleet
   - Encrypts GK with each drone's session key
   - Broadcasts commands encrypted with GK
   - Includes HMAC for integrity

**Command Line Options:**
```bash
python3 mcc.py --host <host> --port <port> --security-level <bits>

Options:
  --host            Host to bind (default: localhost)
  --port            Port to listen (default: 5555)
  --security-level  Prime bit length: 512, 1024, 2048, 3072 (default: 2048)
```

**Interactive Commands:**
```
MCC> list              # Show all authenticated drones
MCC> broadcast <cmd>   # Send command to all drones
MCC> status            # Show server status
MCC> shutdown          # Gracefully close server
```

### File 3: drone.py

**Purpose:** UAV Drone client - connects to MCC and executes commands

**Key Components:**

1. **Connection & Phase 0**
   - Connects to MCC TCP server
   - Receives cryptographic parameters
   - Verifies MCC's signature on parameters
   - Generates own ElGamal keypair

2. **Phase 1A: Authentication Request**
   - Generates shared secret KD
   - Encrypts KD with MCC's public key
   - Includes timestamp and nonce
   - Signs entire message

3. **Phase 1B: Receive MCC Response**
   - Receives MCC's authentication
   - Verifies MCC's signature
   - Decrypts and verifies shared secret

4. **Phase 2: Session Key Derivation**
   - Computes SK = SHA256(KD || TS_D || TS_MCC || RN_D || RN_MCC)
   - Sends HMAC(SK, confirmation) to MCC
   - Session established

5. **Phase 3: Command Reception**
   - Receives encrypted group key
   - Receives encrypted commands
   - Verifies HMAC on all messages
   - Executes commands

**Command Line Options:**
```bash
python3 drone.py --id <ID> --mcc-host <host> --mcc-port <port>

Options:
  --id        Unique drone identifier (e.g., D001)
  --mcc-host  MCC server hostname (default: localhost)
  --mcc-port  MCC server port (default: 5555)
```

**Supported Commands:**
- `TAKEOFF` - Initiates takeoff sequence
- `LAND` - Initiates landing sequence
- `HOVER` - Maintains current position
- `RETURN_TO_BASE` - Returns to home location
- `STATUS` - Reports current status
- `EMERGENCY_STOP` - Emergency shutdown

### File 4: attacks.py

**Purpose:** Security attack demonstrations showing system defenses

**Attack Scenarios:**

1. **Replay Attack** - Replaying old authentication messages
2. **Man-in-the-Middle** - Intercepting and modifying parameters
3. **Unauthorized Access** - Connecting with unknown drone ID
4. **Message Tampering** - Modifying encrypted commands
5. **Drone Impersonation** - Pretending to be legitimate drone

**Command Line Options:**
```bash
python3 attacks.py --mcc-host <host> --mcc-port <port> [--auto]

Options:
  --mcc-host  MCC server hostname (default: localhost)
  --mcc-port  MCC server port (default: 5555)
  --auto      Run all attacks automatically (non-interactive)
```

**Running Modes:**

1. **Automatic Mode** (runs all attacks sequentially):
```bash
python3 attacks.py --auto
```

2. **Interactive Mode** (choose attacks individually):
```bash
python3 attacks.py
```

Interactive menu:
```
ATTACK MENU
======================================================================
Available Attacks:
  [r] - Replay Attack
  [m] - Man-in-the-Middle (MITM) Attack
  [u] - Unauthorized Access Attack
  [t] - Message Tampering Attack
  [i] - Drone Impersonation Attack
  [a] - Run All Attacks Sequentially
  [q] - Quit
======================================================================
Select attack [r/m/u/t/i/a/q]: 
```

---

## 🛡️ Security Attack Demonstrations

### Prerequisites

1. **MCC server must be running** (Terminal 1)
2. **At least 1 drone connected** (Terminal 2) - for replay attack
3. **Terminal 3** - for running attacks

### Attack 1: Replay Attack

**Objective:** Capture legitimate authentication and replay it later to gain unauthorized access

**How it works:**
1. Attacker captures drone's Phase 1A authentication message
2. Waits 35 seconds (beyond timestamp validation window)
3. Attempts to replay captured message

**Run:**
```bash
python3 attacks.py --auto
# Or interactive: python3 attacks.py → select 'r'
```

**Expected Output:**
```
======================================================================
ATTACK 1: REPLAY ATTACK
======================================================================
Objective: Replay old authentication message to gain access
Expected Defense: Timestamp validation

[REPLAY ATTACK] Step 1: Capturing legitimate authentication...
[REPLAY ATTACK] Received Phase 0 from MCC (1024 bytes)
[REPLAY ATTACK] Captured authentication data for D001
[REPLAY ATTACK] Step 2: Waiting 35 seconds before replay...
[REPLAY ATTACK] Step 3: Attempting to replay authentication...
[REPLAY ATTACK] Received new Phase 0
[REPLAY ATTACK] Replaying old Phase 1A message...
[REPLAY ATTACK] ✓ MCC REJECTED replay due to old timestamp!
[REPLAY ATTACK]   Result: ATTACK PREVENTED
======================================================================
```

**Possible Outcomes:**

| Scenario | Output | Reason |
|----------|--------|--------|
| **Success (Defense Works)** | `✓ ATTACK PREVENTED` | Timestamp validation rejected old message (>30s) |
| **System Clock Sync Issue** | `✗ Timestamp accepted` | Clocks not synchronized (rare) |
| **No Response** | `✗ No response` | MCC crashed or network error |

**Defense Mechanism:**
- **Timestamp Validation**: MCC checks `|current_time - ts_drone| < 30 seconds`
- Messages older than 30 seconds are rejected
- Fresh nonces ensure unique sessions

---

### Attack 2: Man-in-the-Middle (MitM) Attack

**Objective:** Intercept Phase 0 and modify cryptographic parameters to weaken security

**How it works:**
1. Attacker positions between MCC and drone
2. Intercepts Phase 0 parameter distribution
3. Attempts to replace 2048-bit prime with weak 512-bit prime
4. Tries to forward modified parameters

**Run:**
```bash
python3 attacks.py --auto
# Or interactive: python3 attacks.py → select 'm'
```

**Expected Output:**
```
======================================================================
ATTACK 2: MAN-IN-THE-MIDDLE ATTACK (Phase 0)
======================================================================
Objective: Intercept and modify cryptographic parameters
Expected Defense: Signature verification

[MItM ATTACK] Attempting to set up proxy attack...
[MItM ATTACK] Step 1: Intercept MCC -> Drone connection
[MItM ATTACK] Step 2: Receive Phase 0 parameters from MCC
[MItM ATTACK] Step 3: Modify parameters to weaken encryption
[MItM ATTACK] Tampering with parameters...
[MItM ATTACK] Attempting to replace p with weak 512-bit prime...
[MItM ATTACK] Generated weak prime: 512 bits
[MItM ATTACK] Cannot re-sign with attacker's key (no private key)
[MItM ATTACK] ✓ Cannot re-sign tampered parameters!
[MItM ATTACK] ✓ Drone will reject due to signature failure!
[MItM ATTACK]   Result: ATTACK PREVENTED
======================================================================
```

**Possible Outcomes:**

| Scenario | Output | Reason |
|----------|--------|--------|
| **Success (Defense Works)** | `✓ ATTACK PREVENTED` | Attacker cannot sign modified parameters |
| **If Signatures Disabled** | `✗ Weak parameters accepted` | Would succeed if no signature verification |
| **Drone Not Verifying** | `✗ Tampering successful` | Implementation bug (shouldn't happen) |

**Defense Mechanism:**
- **Digital Signatures**: MCC signs all Phase 0 parameters with private key
- Drone verifies signature using MCC's public key
- Tampering detection: Modified parameters → invalid signature → rejection

---

### Attack 3: Unauthorized Access

**Objective:** Connect to MCC with unknown/rogue drone ID without authorization

**How it works:**
1. Attacker generates own ElGamal keypair
2. Attempts to connect as "ROGUE_DRONE"
3. Sends Phase 1A with fake credentials
4. MCC has no record of this drone's public key

**Run:**
```bash
python3 attacks.py --auto
# Or interactive: python3 attacks.py → select 'u'
```

**Expected Output:**
```
======================================================================
ATTACK 3: UNAUTHORIZED ACCESS
======================================================================
Objective: Connect to MCC with unknown/invalid drone ID
Expected Defense: Unknown public key, signature verification

[UNAUTHORIZED] Attacker ID: ROGUE_DRONE
[UNAUTHORIZED] Step 1: Generate own keypair
[UNAUTHORIZED] Generated keypair with Y=123456789...
[UNAUTHORIZED] Step 2: Attempt connection to MCC
[UNAUTHORIZED] Connected to MCC
[UNAUTHORIZED] Received Phase 0 from MCC
[UNAUTHORIZED] Step 3: Sending Phase 1A with unknown ID
[UNAUTHORIZED] Sent Phase 1A
[UNAUTHORIZED] ✓ MCC REJECTED connection!
[UNAUTHORIZED]   Reason: Invalid signature verification
[UNAUTHORIZED]   Result: ATTACK PREVENTED
======================================================================
```

**Possible Outcomes:**

| Scenario | Output | Reason |
|----------|--------|--------|
| **Success (Defense Works)** | `✓ ATTACK PREVENTED` | MCC rejects unknown drone (no pre-shared public key) |
| **Connection Timeout** | `✓ Connection timeout` | MCC closes connection immediately |
| **If PKI Not Enforced** | `✗ Connection accepted` | Would succeed without proper PKI (design flaw) |

**Defense Mechanism:**
- **Public Key Infrastructure**: MCC must know drone's public key beforehand
- **Signature Verification**: MCC verifies drone's signature using registered public key
- **Unknown Drones Rejected**: No public key → cannot verify → reject connection

---

### Attack 4: Message Tampering

**Objective:** Modify encrypted broadcast command without detection

**How it works:**
1. Attacker intercepts encrypted command
2. Flips bits in ciphertext to modify command
3. Attempts to forward modified ciphertext
4. HMAC verification should detect tampering

**Run:**
```bash
python3 attacks.py --auto
# Or interactive: python3 attacks.py → select 't'
```

**Expected Output:**
```
======================================================================
ATTACK 4: MESSAGE TAMPERING
======================================================================
Objective: Modify broadcast command and avoid detection
Expected Defense: HMAC authentication

[TAMPERING] Original command: RETURN_TO_BASE
[TAMPERING] HMAC: 3a7bd3e2f1c9d4e5a6b7c8d9e0f1a2b3...
[TAMPERING] Attacker modifies ciphertext...
[TAMPERING] Tampered ciphertext HMAC: 9f8e7d6c5b4a39281726f5e4d3c2b1a0...
[TAMPERING] Step: Verify HMAC
[TAMPERING] ✓ HMAC mismatch detected!
[TAMPERING]   Result: ATTACK PREVENTED
======================================================================
```

**Possible Outcomes:**

| Scenario | Output | Reason |
|----------|--------|--------|
| **Success (Defense Works)** | `✓ ATTACK PREVENTED` | HMAC mismatch detected, message rejected |
| **HMAC Not Verified** | `✗ Tampering not detected` | Would succeed if HMAC check skipped |
| **Wrong Key Used** | `✗ Decryption failed` | Garbled plaintext after decryption |

**Defense Mechanism:**
- **HMAC-SHA256**: Every broadcast includes HMAC(session_key, ciphertext)
- **Verification Before Decryption**: Drone verifies HMAC first
- **Tampering Detection**: Modified ciphertext → HMAC mismatch → reject message

---

### Attack 5: Drone Impersonation

**Objective:** Impersonate legitimate drone (e.g., D001) using rogue credentials

**How it works:**
1. Attacker generates own keypair
2. Claims to be legitimate drone "D001"
3. Sends Phase 1A with D001 ID but rogue signature
4. MCC verifies signature using D001's registered public key

**Run:**
```bash
python3 attacks.py --auto
# Or interactive: python3 attacks.py → select 'i'
```

**Expected Output:**
```
======================================================================
ATTACK 5: DRONE IMPERSONATION
======================================================================
Objective: Impersonate legitimate drone D001
Expected Defense: Digital signatures and PKI

[IMPERSONATION] Target: D001
[IMPERSONATION] Step 1: Generate rogue keypair
[IMPERSONATION] Generated rogue keypair
[IMPERSONATION] Step 2: Attempt connection as target drone
[IMPERSONATION] Connected to MCC
[IMPERSONATION] Received MCC parameters
[IMPERSONATION] Sending Phase 1A as D001
[IMPERSONATION] Awaiting response...
[IMPERSONATION] ✓ MCC REJECTED impersonation!
[IMPERSONATION]   Reason: Signature verification failed
[IMPERSONATION]   Result: ATTACK PREVENTED
======================================================================
```

**Possible Outcomes:**

| Scenario | Output | Reason |
|----------|--------|--------|
| **Success (Defense Works)** | `✓ ATTACK PREVENTED` | Signature doesn't match D001's registered public key |
| **Connection Timeout** | `✓ Connection timeout` | MCC detects invalid signature and closes connection |
| **If Weak PKI** | `✗ Impersonation successful` | Would succeed without proper signature verification |

**Defense Mechanism:**
- **Digital Signatures**: Every message signed with private key
- **Public Key Registry**: MCC maintains mapping: Drone_ID → Public_Key
- **Signature Verification**: MCC verifies using D001's registered public key, not attacker's
- **Impersonation Detection**: Rogue signature → verification fails → reject

---

### Attack Summary Table

| Attack | Defense Mechanism | Status | Time to Run |
|--------|------------------|--------|-------------|
| **Replay Attack** | Timestamp validation (30s window) | ✅ PREVENTED | ~40 seconds |
| **Man-in-the-Middle** | Digital signatures on parameters | ✅ PREVENTED | ~2 seconds |
| **Unauthorized Access** | Public Key Infrastructure (PKI) | ✅ PREVENTED | ~3 seconds |
| **Message Tampering** | HMAC-SHA256 authentication | ✅ PREVENTED | ~1 second |
| **Drone Impersonation** | Signature verification with PKI | ✅ PREVENTED | ~3 seconds |

**Total Runtime (all attacks):** ~50 seconds

---

## 📋 Command Reference
## 📋 Command Reference

### MCC Interactive Commands

```
MCC> list
```
- **Description**: Display all connected and authenticated drones
- **Output**: Table with Drone ID, Address, and Status

```
MCC> broadcast <COMMAND>
```
- **Description**: Send command to all authenticated drones
- **Available Commands**:
  - `TAKEOFF` - Initiates takeoff sequence
  - `LAND` - Initiates landing sequence  
  - `HOVER` - Maintains current position
  - `RETURN_TO_BASE` - Returns to home location
  - `STATUS` - Request status report
  - `EMERGENCY_STOP` - Emergency shutdown
- **Example**: `MCC> broadcast TAKEOFF`

```
MCC> status
```
- **Description**: Show MCC server status
- **Output**: Active connections, uptime, security level

```
MCC> shutdown
```
- **Description**: Gracefully shut down MCC server
- **Action**: Closes all drone connections, cleans up resources

---

## 🔧 Troubleshooting

### "Connection refused" Error

**Issue:** Drone cannot connect to MCC
- **Solution:** Make sure MCC is running in Terminal 1

### "Address already in use" Error

**Issue:** Port 5555 already in use
- **Solution:** Use different port
  ```bash
  python mcc.py --port 5556
  python drone.py --mcc-port 5556
  ```

### Prime Generation Takes Too Long

**Issue:** Cryptographic parameter generation is slow
- **Cause:** Miller-Rabin primality test on large primes
- **Solution:** 
  - Use smaller security level (512-bit for testing)
    ```bash
    python mcc.py --security-level 512
    ```
  - Or wait (normal: 1-2 seconds for 2048-bit)

### "HMAC verification failed" Error

**Issue:** Drone rejects broadcast command
- **Cause:** Usually indicates session key mismatch
- **Solution:**
  - Ensure all drones authenticate before broadcast
  - Wait for "Entering listening mode" message from drones

### "ModuleNotFoundError: No module named 'Crypto'"

**Issue:** PyCryptodome not installed
- **Solution:**
  ```bash
  pip install pycryptodome==3.19.0
  ```

---

## Performance Tips

### For Faster Testing

Use 512-bit security level:
```bash
python mcc.py --security-level 512
```

### For Production

Use 2048-bit (default) or 3072-bit:
```bash
python mcc.py --security-level 2048
python mcc.py --security-level 3072  # More secure but slower
```

### Scale Testing

Test with multiple drones:
```bash
# Terminal 2-6: Run each in separate terminal
for i in {1..5}; do python drone.py --id D$i & done

# Then in MCC
MCC> list
```

---

## What Each Phase Does

### Phase 0: Parameter Distribution
- MCC sends cryptographic parameters to drone
- Drone generates its own keypair
- **Security:** Signature verification on parameters

### Phase 1: Mutual Authentication
- **1A:** Drone sends authentication request with shared secret
- **1B:** MCC responds confirming shared secret
- **Security:** Digital signatures, shared secret encryption

### Phase 2: Session Key Derivation
- Both parties derive same session key
- Confirmation via HMAC
- **Security:** Mutual key agreement proof

### Phase 3: Group Communication
- MCC sends group key to authenticated drones
- MCC broadcasts commands encrypted with group key
- **Security:** HMAC authentication on all broadcasts

---

## Security Features Demonstrated

✓ **Mutual Authentication**: Both parties verify each other  
✓ **Digital Signatures**: Non-repudiation of all messages  
✓ **ElGamal Encryption**: Asymmetric encryption for sensitive data  
✓ **AES-256 Encryption**: Symmetric encryption for broadcasts  
✓ **HMAC-SHA256**: Message authentication codes  
✓ **Timestamp Validation**: Replay attack prevention  
✓ **Nonce Generation**: Session uniqueness  
✓ **Forward Secrecy**: Each session has unique keys  

---

## Example Session

```bash
# Terminal 1
$ python mcc.py
[MCC] Initialized successfully
[MCC] Server listening on localhost:5555
MCC> 

# Terminal 2
$ python drone.py --id D001
[D001] Initialized
[D001] Connected to MCC
[D001] Phase 0: Received parameters
[D001] Generating own key pair...
[D001] Phase 1A: Sent authentication request
[D001] Phase 1B: Received MCC response
[D001] Phase 2: Sent session key confirmation
[D001] Authentication successful!
[D001] Entering listening mode...

# Terminal 3
$ python drone.py --id D002
[D002] Initialized
[D002] Connected to MCC
[D002] Authentication successful!
[D002] Entering listening mode...

# Terminal 1 (MCC)
MCC> list
Active Drones:
D001  | Authenticated
D002  | Authenticated

MCC> broadcast TAKEOFF
[MCC] Broadcast to D001
[MCC] Broadcast to D002

# Terminals 2 & 3 (Drones)
[D001] Received command: TAKEOFF
[D001] >> Executing: Taking off...

[D002] Received command: TAKEOFF
[D002] >> Executing: Taking off...

# Terminal 1 (MCC)
MCC> shutdown
```

---

## Next Steps

1. **Review Security Analysis:** Read `SECURITY.md` for detailed security properties
2. **Inspect Code:** Study how cryptographic functions are implemented
3. **Run Attacks:** Execute `attacks.py` to see security mechanisms in action
4. **Modify & Experiment:** Try changing parameters and observe effects
5. **Scale Testing:** Connect more drones and broadcast complex commands

---

**Happy Secure Flying!** 🚁🔐
