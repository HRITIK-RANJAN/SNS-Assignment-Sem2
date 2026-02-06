# Secure UAV Command and Control System - Implementation Plan

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

---

## 📁 Project Structure

```
project/
├── crypto_utils.py       # Core cryptographic primitives (MANUAL)
├── mcc.py               # Mission Control Center server
├── drone.py             # Drone client implementation
├── attacks.py           # Security attack demonstrations
├── SECURITY.md          # Security analysis document
├── README.md            # This file + performance logs
├── requirements.txt     # Python dependencies (if using Python)
└── tests/              # Optional: unit tests for crypto functions
    ├── test_crypto.py
    ├── test_protocol.py
    └── test_attacks.py
```

---

## 🔐 Phase-by-Phase Implementation Plan

### **PHASE 0: Development Environment Setup**

#### Step 0.1: Choose Programming Language
- **Decision Point**: Python (recommended for rapid development) vs C/C++ (for performance)
- **If Python**: Set up virtual environment
  ```bash
  python3 -m venv venv
  source venv/bin/activate  # Linux/Mac
  # or
  venv\Scripts\activate     # Windows
  ```
- **If C/C++**: Install GMP library for large number arithmetic

#### Step 0.2: Install Permitted Libraries
Create `requirements.txt` (Python):
```
pycryptodome==3.19.0  # For AES-CBC only
```

#### Step 0.3: Project Initialization
- Create all necessary files
- Set up version control (git recommended)
- Create test data directory

---

### **PHASE 1: Core Cryptographic Primitives (crypto_utils.py)**

This is the **MOST CRITICAL** phase. All implementations must be manual.

#### Step 1.1: Helper Mathematical Functions

**Priority: CRITICAL** | **Estimated Time: 4-6 hours**

Implement the following functions:

```python
def modular_exponentiation(base, exponent, modulus):
    """
    Compute (base^exponent) % modulus efficiently using binary method
    
    Algorithm: Square-and-multiply method
    Time Complexity: O(log exponent)
    
    Example: 3^5 mod 7 = 5
    """
    # TODO: Implement binary exponentiation
    pass

def extended_euclidean(a, b):
    """
    Extended Euclidean Algorithm
    Returns (gcd, x, y) such that ax + by = gcd(a,b)
    
    Used for computing modular inverse
    """
    # TODO: Implement extended Euclidean algorithm
    pass

def modular_inverse(a, m):
    """
    Compute a^(-1) mod m using Extended Euclidean
    
    Returns: x such that (a * x) % m == 1
    Raises: ValueError if gcd(a, m) != 1
    """
    # TODO: Use extended_euclidean to find inverse
    pass

def gcd(a, b):
    """
    Compute Greatest Common Divisor
    """
    # TODO: Implement Euclidean algorithm
    pass
```

**Testing Requirements:**
- Test `modular_exponentiation` with known values
- Verify `modular_inverse(a, m) * a % m == 1`
- Edge cases: a=0, m=1, coprime validation

#### Step 1.2: Prime Number Generation

**Priority: CRITICAL** | **Estimated Time: 3-4 hours**

```python
def is_prime_miller_rabin(n, k=40):
    """
    Miller-Rabin primality test
    
    Args:
        n: Number to test
        k: Number of rounds (40 gives good confidence)
    
    Returns: True if probably prime, False if composite
    """
    # TODO: Implement Miller-Rabin algorithm
    pass

def generate_large_prime(bit_length):
    """
    Generate a random prime of specified bit length
    
    Args:
        bit_length: SL parameter (2048 or 3072)
    
    Returns: A prime p where 2^(SL-1) < p < 2^SL
    """
    # TODO: 
    # 1. Generate random odd number in range
    # 2. Test with Miller-Rabin
    # 3. If composite, increment by 2 and retry
    pass

def find_generator(p):
    """
    Find a primitive root (generator) modulo p
    
    Args:
        p: Prime modulus
    
    Returns: A generator g such that g generates all elements mod p
    """
    # TODO: Implement generator finding algorithm
    # Hint: Check if g^((p-1)/q) != 1 for all prime factors q of (p-1)
    pass
```

**Testing Requirements:**
- Generate multiple 2048-bit primes and verify primality
- Verify generator property: order of g should be p-1
- **Performance Benchmark**: Log prime generation time

#### Step 1.3: ElGamal Key Generation

**Priority: CRITICAL** | **Estimated Time: 2-3 hours**

```python
class ElGamalKey:
    """Container for ElGamal public/private keys"""
    def __init__(self, p, g, x=None, y=None):
        self.p = p          # Prime modulus
        self.g = g          # Generator
        self.x = x          # Private key (secret)
        self.y = y          # Public key = g^x mod p
        self.sl = None      # Security level (bit length)

def generate_elgamal_keypair(p, g):
    """
    Generate ElGamal key pair
    
    Args:
        p: Prime modulus
        g: Generator
    
    Returns: ElGamalKey object with both public and private components
    """
    # TODO:
    # 1. Generate random private key x in [1, p-2]
    # 2. Compute public key y = g^x mod p
    # 3. Return ElGamalKey object
    pass
```

#### Step 1.4: ElGamal Encryption/Decryption

**Priority: CRITICAL** | **Estimated Time: 3-4 hours**

```python
def elgamal_encrypt(message, public_key):
    """
    ElGamal Encryption
    
    Args:
        message: Integer message m (must be < p)
        public_key: ElGamalKey with (p, g, y)
    
    Returns: Tuple (c1, c2) where:
        c1 = g^k mod p
        c2 = (m * y^k) mod p
    """
    # TODO:
    # 1. Generate random k in [1, p-2]
    # 2. Compute c1 = g^k mod p
    # 3. Compute c2 = (m * y^k) mod p
    # 4. Return (c1, c2)
    pass

def elgamal_decrypt(ciphertext, private_key):
    """
    ElGamal Decryption
    
    Args:
        ciphertext: Tuple (c1, c2)
        private_key: ElGamalKey with (p, g, x)
    
    Returns: Original message m = c2 * (c1^x)^(-1) mod p
    """
    # TODO:
    # 1. Unpack c1, c2
    # 2. Compute s = c1^x mod p
    # 3. Compute s_inv = modular_inverse(s, p)
    # 4. Compute m = (c2 * s_inv) mod p
    # 5. Return m
    pass
```

**Testing Requirements:**
- Encrypt then decrypt: verify `decrypt(encrypt(m)) == m`
- Test with edge cases: m=1, m=p-1
- Test with different message sizes

#### Step 1.5: ElGamal Digital Signatures

**Priority: CRITICAL** | **Estimated Time: 4-5 hours**

```python
def elgamal_sign(message_hash, private_key):
    """
    ElGamal Digital Signature
    
    Args:
        message_hash: Integer hash H(m) of the message
        private_key: ElGamalKey with (p, g, x)
    
    Returns: Signature tuple (r, s) where:
        r = g^k mod p
        s = (H(m) - x*r) * k^(-1) mod (p-1)
    """
    # TODO:
    # 1. Generate random k such that gcd(k, p-1) = 1
    # 2. Compute r = g^k mod p
    # 3. Compute k_inv = modular_inverse(k, p-1)
    # 4. Compute s = ((H(m) - x*r) * k_inv) mod (p-1)
    # 5. Return (r, s)
    pass

def elgamal_verify(message_hash, signature, public_key):
    """
    ElGamal Signature Verification
    
    Args:
        message_hash: Integer hash H(m)
        signature: Tuple (r, s)
        public_key: ElGamalKey with (p, g, y)
    
    Returns: True if valid, False otherwise
    
    Verification: Check if g^H(m) ≡ y^r * r^s (mod p)
    """
    # TODO:
    # 1. Unpack r, s
    # 2. Compute left = g^H(m) mod p
    # 3. Compute right = (y^r * r^s) mod p
    # 4. Return left == right
    pass
```

**Testing Requirements:**
- Sign then verify: verify should return True
- Modify signature: verify should return False
- Modify message: verify should return False

#### Step 1.6: Hash and MAC Functions

**Priority: HIGH** | **Estimated Time: 1-2 hours**

```python
import hashlib
import hmac

def hash_sha256(data):
    """
    SHA-256 hash function
    
    Args:
        data: bytes or string to hash
    
    Returns: bytes (32-byte hash)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def hmac_sha256(key, data):
    """
    HMAC-SHA256 authentication code
    
    Args:
        key: Secret key (bytes)
        data: Message to authenticate (bytes)
    
    Returns: bytes (32-byte HMAC)
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hmac.new(key, data, hashlib.sha256).digest()
```

#### Step 1.7: AES-256 CBC Mode (Phase 3 Only)

**Priority: MEDIUM** | **Estimated Time: 2 hours**

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def aes_encrypt(key, plaintext):
    """
    AES-256 encryption in CBC mode
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt (bytes)
    
    Returns: (iv, ciphertext) tuple
    """
    # TODO:
    # 1. Generate random 16-byte IV
    # 2. Create AES cipher in CBC mode
    # 3. Pad plaintext to block size
    # 4. Encrypt
    # 5. Return (iv, ciphertext)
    pass

def aes_decrypt(key, iv, ciphertext):
    """
    AES-256 decryption in CBC mode
    
    Args:
        key: 32-byte encryption key
        iv: 16-byte initialization vector
        ciphertext: Encrypted data
    
    Returns: Original plaintext (bytes)
    """
    # TODO:
    # 1. Create AES cipher with same IV
    # 2. Decrypt
    # 3. Unpad
    # 4. Return plaintext
    pass
```

#### Step 1.8: Message Encoding/Decoding

**Priority: HIGH** | **Estimated Time: 2-3 hours**

```python
def bytes_to_int(data):
    """Convert bytes to integer for ElGamal encryption"""
    return int.from_bytes(data, byteorder='big')

def int_to_bytes(n, length=None):
    """Convert integer back to bytes"""
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder='big')

def split_message(message, chunk_size):
    """
    Split large message into chunks that fit in ElGamal
    
    Args:
        message: bytes to split
        chunk_size: Maximum chunk size (must be < p)
    
    Returns: List of byte chunks
    """
    # TODO: Split message into manageable pieces
    pass

def join_chunks(chunks):
    """Reassemble message from chunks"""
    return b''.join(chunks)
```

---

### **PHASE 2: Mission Control Center (mcc.py)**

**Priority: CRITICAL** | **Estimated Time: 8-10 hours**

#### Step 2.1: MCC Initialization

```python
class MissionControlCenter:
    def __init__(self, host='localhost', port=5555, security_level=2048):
        """
        Initialize MCC Server
        
        Args:
            host: Bind address
            port: Listen port
            security_level: Bit length for prime (2048 or 3072)
        """
        self.host = host
        self.port = port
        self.security_level = security_level
        
        # Generate MCC's ElGamal keys
        print("[MCC] Generating cryptographic parameters...")
        self.p = generate_large_prime(security_level)
        self.g = find_generator(self.p)
        self.keypair = generate_elgamal_keypair(self.p, self.g)
        
        # Thread-safe drone registry
        self.drones = {}  # {drone_id: DroneSession}
        self.drones_lock = threading.Lock()
        
        # Server socket
        self.server_socket = None
        self.running = False
        
        print(f"[MCC] Initialized with SL={security_level}")
        print(f"[MCC] Public Key Y: {self.keypair.y}")
```

#### Step 2.2: Drone Session Management

```python
class DroneSession:
    """Represents a connected drone's session state"""
    def __init__(self, drone_id, socket, address):
        self.drone_id = drone_id
        self.socket = socket
        self.address = address
        self.drone_public_key = None
        self.shared_secret = None  # KDi,MCC
        self.session_key = None    # SKDi,MCC
        self.authenticated = False
        self.timestamp_auth = None
```

#### Step 2.3: Phase 0 - Parameter Distribution

```python
def send_phase0_params(self, client_socket):
    """
    Phase 0: Send crypto parameters to drone
    
    Message Structure:
    - OPCODE 10 (1 byte)
    - p (variable bytes)
    - g (variable bytes)
    - SL (4 bytes)
    - Timestamp (8 bytes)
    - IDMCC (variable)
    - Signature (variable)
    """
    # TODO:
    # 1. Create timestamp
    # 2. Prepare message M0 = p || g || SL || TS0 || IDMCC
    # 3. Sign M0 with MCC's private key
    # 4. Pack into protocol format
    # 5. Send to client
    pass
```

#### Step 2.4: Phase 1A - Process Drone Authentication Request

```python
def process_phase1a_auth_request(self, data, client_socket):
    """
    Phase 1A: Process incoming drone authentication
    
    Receives:
    - OPCODE 20
    - TSi (timestamp)
    - RNi (nonce)
    - IDDi (drone ID)
    - Ci (encrypted KDi,MCC)
    - Signature
    
    Validates:
    - Timestamp freshness (within 30 seconds)
    - Signature verification
    - Drone not blocked
    """
    # TODO:
    # 1. Parse incoming message
    # 2. Verify timestamp freshness
    # 3. Lookup drone's public key (pre-shared or from PKI)
    # 4. Verify signature
    # 5. Decrypt Ci to get KDi,MCC
    # 6. Store in temporary session state
    # 7. Proceed to Phase 1B
    pass
```

#### Step 2.5: Phase 1B - Send MCC Response

```python
def send_phase1b_response(self, session, KDi_MCC):
    """
    Phase 1B: Send MCC authentication response
    
    Sends:
    - OPCODE 30
    - TSMCC (timestamp)
    - RNMCC (nonce)
    - IDMCC
    - CMCC (encrypted KDi,MCC)
    - Signature
    """
    # TODO:
    # 1. Generate MCC timestamp and nonce
    # 2. Encrypt KDi,MCC with drone's public key
    # 3. Create message M1B
    # 4. Sign M1B
    # 5. Send to drone
    pass
```

#### Step 2.6: Phase 2 - Session Key Derivation & Confirmation

```python
def process_phase2_confirmation(self, session, data):
    """
    Phase 2: Verify drone's session key confirmation
    
    Both parties derive:
    SKDi,MCC = SHA256(KDi,MCC || TSi || TSMCC || RNi || RNMCC)
    
    Receives:
    - OPCODE 40
    - HMAC-SHA256(SKDi,MCC, IDDi || TSfinal)
    """
    # TODO:
    # 1. Derive session key using same formula
    # 2. Compute expected HMAC
    # 3. Compare with received HMAC
    # 4. If match:
    #    - Send OPCODE 50 (SUCCESS)
    #    - Register drone in active registry
    # 5. If mismatch:
    #    - Send OPCODE 60 (ERROR)
    #    - Block drone ID
    pass
```

#### Step 2.7: Concurrent Connection Handling

```python
def handle_drone_connection(self, client_socket, address):
    """
    Thread function to handle a single drone connection
    
    Flow:
    1. Send Phase 0 parameters
    2. Receive and process Phase 1A
    3. Send Phase 1B response
    4. Receive and process Phase 2 confirmation
    5. Keep connection alive for commands
    """
    try:
        print(f"[MCC] New connection from {address}")
        
        # Phase 0
        self.send_phase0_params(client_socket)
        
        # Phase 1A
        data = client_socket.recv(4096)
        session = self.process_phase1a_auth_request(data, client_socket)
        
        # Phase 1B
        self.send_phase1b_response(session)
        
        # Phase 2
        data = client_socket.recv(4096)
        self.process_phase2_confirmation(session, data)
        
        # Keep alive for commands
        while self.running:
            # Listen for drone status updates
            pass
            
    except Exception as e:
        print(f"[MCC] Error handling drone: {e}")
    finally:
        client_socket.close()

def start_server(self):
    """
    Main server loop - accepts connections and spawns threads
    """
    self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.server_socket.bind((self.host, self.port))
    self.server_socket.listen(5)
    self.running = True
    
    print(f"[MCC] Server listening on {self.host}:{self.port}")
    
    while self.running:
        client_socket, address = self.server_socket.accept()
        thread = threading.Thread(
            target=self.handle_drone_connection,
            args=(client_socket, address)
        )
        thread.start()
```

#### Step 2.8: Command Line Interface

```python
def cli_interface(self):
    """
    Interactive CLI for MCC operator
    
    Commands:
    - list: Show all authenticated drones
    - broadcast <cmd>: Send command to all drones
    - shutdown: Close all connections
    """
    print("\n[MCC] Command Interface Ready")
    print("Commands: list | broadcast <cmd> | shutdown")
    
    while self.running:
        try:
            user_input = input("MCC> ").strip()
            
            if user_input == "list":
                self.cmd_list_drones()
            elif user_input.startswith("broadcast "):
                cmd = user_input[10:]
                self.cmd_broadcast(cmd)
            elif user_input == "shutdown":
                self.cmd_shutdown()
                break
            else:
                print("Unknown command")
                
        except KeyboardInterrupt:
            print("\n[MCC] Shutting down...")
            self.cmd_shutdown()
            break

def cmd_list_drones(self):
    """Display all connected drones"""
    with self.drones_lock:
        if not self.drones:
            print("No drones connected")
            return
        
        print("\nActive Drones:")
        print("-" * 60)
        for drone_id, session in self.drones.items():
            status = "Authenticated" if session.authenticated else "Connecting"
            print(f"{drone_id:20s} | {session.address} | {status}")
        print("-" * 60)
```

#### Step 2.9: Phase 3 - Group Key Broadcast

```python
def cmd_broadcast(self, command):
    """
    Phase 3: Broadcast command to all drones using group key
    
    Steps:
    1. Aggregate all session keys
    2. Derive group key GK
    3. Send GK to each drone (encrypted with their SK)
    4. Send command encrypted with GK
    """
    with self.drones_lock:
        if not self.drones:
            print("[MCC] No drones to broadcast to")
            return
        
        # Step 1: Collect all session keys
        session_keys = [s.session_key for s in self.drones.values()]
        
        # Step 2: Derive group key
        gk_material = b''.join(session_keys) + self.keypair.x.to_bytes(256, 'big')
        group_key = hash_sha256(gk_material)
        
        print(f"[MCC] Generated Group Key: {group_key.hex()[:32]}...")
        
        # Step 3: Distribute GK to each drone
        for drone_id, session in self.drones.items():
            try:
                # Encrypt GK with drone's session key
                iv, encrypted_gk = aes_encrypt(session.session_key, group_key)
                
                # Send OPCODE 70 (GROUP_KEY)
                msg = struct.pack('B', 70) + iv + encrypted_gk
                session.socket.sendall(msg)
                
                print(f"[MCC] Sent GK to {drone_id}")
            except Exception as e:
                print(f"[MCC] Failed to send GK to {drone_id}: {e}")
        
        # Step 4: Broadcast encrypted command
        time.sleep(1)  # Give drones time to process GK
        
        iv, encrypted_cmd = aes_encrypt(group_key, command.encode('utf-8'))
        hmac_tag = hmac_sha256(group_key, encrypted_cmd)
        
        msg = struct.pack('B', 80) + iv + encrypted_cmd + hmac_tag
        
        for drone_id, session in self.drones.items():
            try:
                session.socket.sendall(msg)
                print(f"[MCC] Broadcast to {drone_id}")
            except Exception as e:
                print(f"[MCC] Failed to broadcast to {drone_id}: {e}")
```

---

### **PHASE 3: Drone Client (drone.py)**

**Priority: CRITICAL** | **Estimated Time: 6-8 hours**

#### Step 3.1: Drone Initialization

```python
class Drone:
    def __init__(self, drone_id, mcc_host='localhost', mcc_port=5555):
        """
        Initialize Drone Client
        
        Args:
            drone_id: Unique identifier for this drone
            mcc_host: MCC server address
            mcc_port: MCC server port
        """
        self.drone_id = drone_id
        self.mcc_host = mcc_host
        self.mcc_port = mcc_port
        
        # Crypto state
        self.p = None
        self.g = None
        self.security_level = None
        self.mcc_public_key = None
        self.keypair = None  # Generated after receiving params
        
        # Session state
        self.shared_secret = None  # KDi,MCC
        self.session_key = None    # SKDi,MCC
        self.group_key = None      # GK for broadcasts
        self.authenticated = False
        
        # Nonces and timestamps
        self.my_nonce = None
        self.my_timestamp = None
        self.mcc_nonce = None
        self.mcc_timestamp = None
        
        # Socket
        self.socket = None
        
        print(f"[{self.drone_id}] Initialized")
```

#### Step 3.2: Phase 0 - Receive Parameters

```python
def receive_phase0_params(self):
    """
    Phase 0: Receive and validate crypto parameters from MCC
    
    Validates:
    - Security level >= 2048
    - Prime p has correct bit length
    - Signature verification
    """
    # TODO:
    # 1. Receive OPCODE 10 message
    # 2. Parse p, g, SL, TS0, IDMCC, signature
    # 3. Verify SL >= 2048 (security policy)
    # 4. Verify len(bin(p)) ≈ SL (detect inconsistency)
    # 5. Verify MCC's signature on parameters
    # 6. If valid, store p, g, SL
    # 7. Generate drone's own ElGamal keypair
    pass
```

#### Step 3.3: Phase 1A - Send Authentication Request

```python
def send_phase1a_auth_request(self):
    """
    Phase 1A: Send authentication request to MCC
    
    Sends:
    - OPCODE 20
    - TSi (timestamp)
    - RNi (256-bit nonce)
    - IDDi (drone ID)
    - Ci (encrypted KDi,MCC)
    - Signature
    """
    # TODO:
    # 1. Generate 256-bit random secret KDi,MCC
    # 2. Generate random nonce RNi
    # 3. Create timestamp TSi
    # 4. Encrypt KDi,MCC with MCC's public key
    # 5. Create message M1A
    # 6. Sign M1A with drone's private key
    # 7. Send to MCC
    pass
```

#### Step 3.4: Phase 1B - Process MCC Response

```python
def receive_phase1b_response(self):
    """
    Phase 1B: Receive and validate MCC authentication response
    
    Receives:
    - OPCODE 30
    - TSMCC
    - RNMCC
    - IDMCC
    - CMCC (encrypted KDi,MCC)
    - Signature
    
    Validates:
    - Timestamp freshness
    - Signature
    - Decrypted key matches original KDi,MCC
    """
    # TODO:
    # 1. Receive message
    # 2. Verify timestamp
    # 3. Verify MCC's signature
    # 4. Decrypt CMCC to get KDi,MCC
    # 5. Compare with original shared secret
    # 6. If match, proceed to Phase 2
    pass
```

#### Step 3.5: Phase 2 - Session Key Confirmation

```python
def send_phase2_confirmation(self):
    """
    Phase 2: Derive session key and send confirmation
    
    Derives:
    SKDi,MCC = SHA256(KDi,MCC || TSi || TSMCC || RNi || RNMCC)
    
    Sends:
    - OPCODE 40
    - HMAC-SHA256(SKDi,MCC, IDDi || TSfinal)
    """
    # TODO:
    # 1. Derive session key
    # 2. Create final timestamp
    # 3. Compute HMAC over (IDDi || TSfinal)
    # 4. Send to MCC
    # 5. Wait for OPCODE 50 (SUCCESS) or 60 (ERROR)
    pass

def wait_for_confirmation(self):
    """Wait for MCC's final confirmation"""
    data = self.socket.recv(1024)
    opcode = struct.unpack('B', data[0:1])[0]
    
    if opcode == 50:  # SUCCESS
        self.authenticated = True
        print(f"[{self.drone_id}] Authentication successful!")
        return True
    elif opcode == 60:  # MISMATCH
        print(f"[{self.drone_id}] Authentication failed!")
        return False
```

#### Step 3.6: Phase 3 - Receive Group Key and Commands

```python
def receive_group_key(self):
    """
    Phase 3: Receive and decrypt group key
    
    Receives:
    - OPCODE 70
    - IV
    - Encrypted GK
    """
    data = self.socket.recv(4096)
    opcode = struct.unpack('B', data[0:1])[0]
    
    if opcode == 70:
        iv = data[1:17]
        encrypted_gk = data[17:]
        
        # Decrypt using session key
        self.group_key = aes_decrypt(self.session_key, iv, encrypted_gk)
        print(f"[{self.drone_id}] Received Group Key")

def receive_broadcast_command(self):
    """
    Receive and process broadcast command
    
    Receives:
    - OPCODE 80
    - IV
    - Encrypted command
    - HMAC tag
    """
    data = self.socket.recv(4096)
    opcode = struct.unpack('B', data[0:1])[0]
    
    if opcode == 80:
        iv = data[1:17]
        encrypted_cmd = data[17:-32]
        received_hmac = data[-32:]
        
        # Verify HMAC
        computed_hmac = hmac_sha256(self.group_key, encrypted_cmd)
        if computed_hmac != received_hmac:
            print(f"[{self.drone_id}] HMAC verification failed!")
            return
        
        # Decrypt command
        command = aes_decrypt(self.group_key, iv, encrypted_cmd)
        print(f"[{self.drone_id}] Received command: {command.decode('utf-8')}")
        
        # Execute command (simulation)
        self.execute_command(command.decode('utf-8'))
```

#### Step 3.7: Main Connection Loop

```python
def connect_to_mcc(self):
    """
    Main connection routine
    
    Flow:
    1. Connect to MCC
    2. Receive Phase 0 parameters
    3. Send Phase 1A authentication
    4. Receive Phase 1B response
    5. Send Phase 2 confirmation
    6. Enter listening mode for commands
    """
    try:
        # Connect
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.mcc_host, self.mcc_port))
        print(f"[{self.drone_id}] Connected to MCC at {self.mcc_host}:{self.mcc_port}")
        
        # Phase 0
        self.receive_phase0_params()
        
        # Phase 1A
        self.send_phase1a_auth_request()
        
        # Phase 1B
        self.receive_phase1b_response()
        
        # Phase 2
        self.send_phase2_confirmation()
        if not self.wait_for_confirmation():
            return False
        
        # Phase 3: Listen for group key and commands
        while True:
            data = self.socket.recv(1)
            if not data:
                break
            
            opcode = struct.unpack('B', data)[0]
            
            if opcode == 70:  # GROUP_KEY
                self.receive_group_key()
            elif opcode == 80:  # GROUP_CMD
                self.receive_broadcast_command()
            elif opcode == 90:  # SHUTDOWN
                print(f"[{self.drone_id}] Received shutdown signal")
                break
        
        return True
        
    except Exception as e:
        print(f"[{self.drone_id}] Connection error: {e}")
        return False
    finally:
        if self.socket:
            self.socket.close()
```

---

### **PHASE 4: Security Testing (attacks.py)**

**Priority: HIGH** | **Estimated Time: 4-5 hours**

#### Attack 1: Replay Attack

```python
def replay_attack():
    """
    Demonstrate replay attack on Phase 1A
    
    Steps:
    1. Capture a valid Phase 1A message
    2. Wait some time
    3. Replay the same message
    4. MCC should reject due to old timestamp
    """
    print("\n=== REPLAY ATTACK ===")
    # TODO:
    # 1. Run legitimate drone connection
    # 2. Capture Phase 1A packet
    # 3. Close connection
    # 4. Wait 60 seconds
    # 5. Replay captured packet
    # 6. Verify MCC rejects it
    pass
```

#### Attack 2: Man-in-the-Middle

```python
def mitm_attack():
    """
    Demonstrate MitM attack on Phase 0
    
    Steps:
    1. Intercept Phase 0 parameters
    2. Modify the prime p to a weak 512-bit value
    3. Re-sign with attacker's key
    4. Forward to drone
    5. Drone should detect inconsistency or signature failure
    """
    print("\n=== MAN-IN-THE-MIDDLE ATTACK ===")
    # TODO:
    # 1. Set up proxy between drone and MCC
    # 2. Intercept Phase 0 message
    # 3. Replace p with weak prime
    # 4. Try to re-sign (will fail - no MCC private key)
    # 5. Drone rejects due to invalid signature
    pass
```

#### Attack 3: Unauthorized Access

```python
def unauthorized_access_attack():
    """
    Attempt to connect with unknown/invalid drone ID
    
    Expected: MCC should reject due to:
    - Unknown public key
    - Invalid signature
    """
    print("\n=== UNAUTHORIZED ACCESS ATTACK ===")
    # TODO:
    # 1. Create rogue drone with unknown ID
    # 2. Generate own keypair
    # 3. Attempt to authenticate
    # 4. MCC cannot verify signature (no public key on record)
    # 5. Connection rejected
    pass
```

---

### **PHASE 5: Documentation**

#### Step 5.1: SECURITY.md

**Priority: HIGH** | **Estimated Time: 2-3 hours**

Create `SECURITY.md` with the following sections:

```markdown
# Security Analysis

## 1. Freshness Guarantees

### Timestamp-Based Freshness
- Each message includes a timestamp
- MCC validates timestamps within 30-second window
- Prevents replay of old messages

### Nonce-Based Freshness
- Random nonces (RNi, RNMCC) included in key derivation
- Session key depends on both nonces
- Even with same KDi,MCC, different session each time

## 2. Forward Secrecy

### Session Key Independence
- Each session derives unique SKDi,MCC
- SK depends on ephemeral nonces
- Compromise of one session doesn't affect others

### Group Key Rotation
- New GK generated for each broadcast
- GK depends on all current session keys
- Drone disconnection forces new GK

## 3. Mutual Authentication

### Drone authenticates MCC
- MCC proves knowledge of KDi,MCC in Phase 1B
- MCC signs all messages with its private key

### MCC authenticates Drone
- Drone signs Phase 1A with its private key
- Signature verified using drone's public key

## 4. Integrity Protection

### Digital Signatures (Phases 0, 1)
- All critical messages signed
- ElGamal signatures prevent tampering

### HMAC (Phases 2, 3)
- Session key confirmation uses HMAC
- Broadcast commands include HMAC tag

## 5. Confidentiality

### Asymmetric Encryption (Phase 1)
- Shared secret encrypted with ElGamal
- Only intended recipient can decrypt

### Symmetric Encryption (Phase 3)
- Group commands encrypted with AES-256-CBC
- Efficient for bulk data

## 6. Attack Resistance

### Replay Attack
- Mitigated by timestamp validation
- Old messages rejected

### MitM Attack
- Mitigated by signature verification
- Tampered parameters detected

### Unauthorized Access
- Mitigated by PKI infrastructure
- Unknown drones cannot authenticate
```

#### Step 5.2: README.md - Performance Section

Add to `README.md`:

```markdown
## Performance Benchmarks

### Test Environment
- CPU: [Your CPU model]
- RAM: [Your RAM]
- OS: [Your OS]
- Language: Python 3.11

### Cryptographic Operations

| Operation | Key Size | Time (ms) | Iterations |
|-----------|----------|-----------|------------|
| Prime Generation | 2048-bit | 1,234 | 10 |
| Modular Exponentiation | 2048-bit | 45 | 1000 |
| ElGamal Encryption | 2048-bit | 67 | 100 |
| ElGamal Decryption | 2048-bit | 89 | 100 |
| ElGamal Sign | 2048-bit | 78 | 100 |
| ElGamal Verify | 2048-bit | 92 | 100 |
| AES-256 Encrypt (1KB) | 256-bit | 0.12 | 1000 |
| HMAC-SHA256 (1KB) | 256-bit | 0.08 | 1000 |

### Protocol Timing

| Phase | Average Time (ms) | Notes |
|-------|-------------------|-------|
| Phase 0 (Param Init) | 1,500 | Includes prime generation |
| Phase 1 (Mutual Auth) | 250 | Two ElGamal operations |
| Phase 2 (SK Confirm) | 15 | Hash + HMAC only |
| Phase 3 (Group Key) | 50 | Per drone |
| Total Handshake | ~1,800 | First connection only |

### Scalability

| Drones | Connection Time (s) | Group Key Distribution (s) |
|--------|---------------------|----------------------------|
| 1 | 1.8 | 0.05 |
| 5 | 1.9 | 0.25 |
| 10 | 2.1 | 0.50 |
| 50 | 3.4 | 2.50 |
| 100 | 6.2 | 5.00 |
```

---

## 🧪 Testing Strategy

### Unit Tests

Create `tests/test_crypto.py`:

```python
import unittest
from crypto_utils import *

class TestModularArithmetic(unittest.TestCase):
    def test_modular_exponentiation(self):
        # Test case: 3^5 mod 7 = 5
        result = modular_exponentiation(3, 5, 7)
        self.assertEqual(result, 5)
    
    def test_modular_inverse(self):
        # Test: (3 * inv(3, 11)) mod 11 == 1
        inv = modular_inverse(3, 11)
        self.assertEqual((3 * inv) % 11, 1)

class TestElGamal(unittest.TestCase):
    def setUp(self):
        # Small prime for fast testing
        self.p = 23
        self.g = 5
        self.keypair = generate_elgamal_keypair(self.p, self.g)
    
    def test_encrypt_decrypt(self):
        message = 10
        ciphertext = elgamal_encrypt(message, self.keypair)
        decrypted = elgamal_decrypt(ciphertext, self.keypair)
        self.assertEqual(message, decrypted)
    
    def test_sign_verify(self):
        message_hash = 42
        signature = elgamal_sign(message_hash, self.keypair)
        valid = elgamal_verify(message_hash, signature, self.keypair)
        self.assertTrue(valid)
```

### Integration Tests

Create `tests/test_protocol.py`:

```python
import unittest
import threading
import time
from mcc import MissionControlCenter
from drone import Drone

class TestProtocol(unittest.TestCase):
    def setUp(self):
        # Start MCC in separate thread
        self.mcc = MissionControlCenter(security_level=512)  # Small for speed
        self.mcc_thread = threading.Thread(target=self.mcc.start_server)
        self.mcc_thread.daemon = True
        self.mcc_thread.start()
        time.sleep(1)  # Wait for server to start
    
    def test_single_drone_connection(self):
        drone = Drone("D001")
        success = drone.connect_to_mcc()
        self.assertTrue(success)
        self.assertTrue(drone.authenticated)
    
    def test_multiple_drones(self):
        drones = [Drone(f"D{i:03d}") for i in range(5)]
        for drone in drones:
            success = drone.connect_to_mcc()
            self.assertTrue(success)
    
    def test_broadcast(self):
        # Connect drones
        drones = [Drone(f"D{i:03d}") for i in range(3)]
        for drone in drones:
            drone.connect_to_mcc()
        
        # Trigger broadcast
        self.mcc.cmd_broadcast("TEST_COMMAND")
        
        # Verify all drones received
        # (Implementation needed in drone.py to capture commands)
```

---

## 📝 Submission Checklist

### Code Files (100% Complete)
- [ ] `crypto_utils.py` - All functions implemented and tested
- [ ] `mcc.py` - Server fully functional with CLI
- [ ] `drone.py` - Client connects and processes all phases
- [ ] `attacks.py` - All three attacks demonstrated

### Documentation (100% Complete)
- [ ] `SECURITY.md` - Freshness and Forward Secrecy explained
- [ ] `README.md` - Performance benchmarks included
- [ ] Code comments - All complex functions documented
- [ ] `requirements.txt` - Dependencies listed

### Testing (100% Complete)
- [ ] Unit tests pass for all crypto functions
- [ ] Integration tests pass for full protocol
- [ ] Attack demonstrations run successfully
- [ ] Performance benchmarks collected

### Video Demo (If Required)
- [ ] Show MCC startup and parameter generation
- [ ] Show multiple drones connecting
- [ ] Show `list` command with active drones
- [ ] Show `broadcast` command execution
- [ ] Show attack demonstrations
- [ ] Explain key security features

---

## 🚀 Quick Start Guide

### Setup (5 minutes)

```bash
# Clone repository
git clone <your-repo>
cd secure-uav-c2

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

### Run Drones (in separate terminals)

```bash
# Terminal 2
python drone.py --id D001 --mcc-host localhost --mcc-port 5555

# Terminal 3
python drone.py --id D002 --mcc-host localhost --mcc-port 5555

# Terminal 4
python drone.py --id D003 --mcc-host localhost --mcc-port 5555
```

### Use MCC CLI

```bash
MCC> list
# Shows all connected drones

MCC> broadcast RETURN_TO_BASE
# Sends command to all drones

MCC> shutdown
# Gracefully closes all connections
```

### Run Attacks

```bash
python attacks.py
```

---

## ⏱️ Time Allocation

| Phase | Task | Estimated Hours |
|-------|------|-----------------|
| 0 | Environment Setup | 0.5 |
| 1 | Cryptographic Primitives | 18-22 |
|   | - Modular arithmetic | 4-6 |
|   | - Prime generation | 3-4 |
|   | - ElGamal key generation | 2-3 |
|   | - ElGamal encryption | 3-4 |
|   | - ElGamal signatures | 4-5 |
|   | - AES/HMAC wrappers | 2-3 |
| 2 | MCC Server | 8-10 |
|   | - Basic structure | 2 |
|   | - Protocol phases | 4-5 |
|   | - Concurrency | 2-3 |
| 3 | Drone Client | 6-8 |
|   | - Basic structure | 1-2 |
|   | - Protocol phases | 3-4 |
|   | - Command handling | 2 |
| 4 | Attack Demonstrations | 4-5 |
| 5 | Documentation | 3-4 |
| 6 | Testing & Debugging | 4-6 |
| **TOTAL** | | **44-55 hours** |

### Recommended Schedule (assuming 5 days)

- **Day 1-2**: Complete Phase 1 (Crypto primitives)
- **Day 3**: Complete Phase 2 (MCC server)
- **Day 4**: Complete Phase 3 (Drone client) + Phase 4 (Attacks)
- **Day 5**: Testing, documentation, final debugging

---

## 🔧 Debugging Tips

### Common Issues

1. **Modular Exponentiation Timeout**
   - Ensure using binary square-and-multiply method
   - Python's built-in `pow(base, exp, mod)` is optimized

2. **Signature Verification Fails**
   - Check gcd(k, p-1) == 1 when generating k
   - Verify all modular arithmetic uses correct modulus

3. **Connection Hangs**
   - Add timeout to socket operations
   - Ensure both parties are in same protocol phase
   - Check for proper message framing

4. **HMAC Mismatch**
   - Verify both parties use same key derivation order
   - Check byte encoding (UTF-8 vs raw bytes)
   - Print intermediate values for comparison

### Logging

Add verbose logging throughout:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
logger.debug(f"Phase 1A: Sending {len(data)} bytes")
```

---

## 📚 Additional Resources

### ElGamal Cryptography
- [Wikipedia: ElGamal encryption](https://en.wikipedia.org/wiki/ElGamal_encryption)
- [Understanding ElGamal signatures](https://www.coursera.org/lecture/asymmetric-crypto/elgamal-signature-scheme)

### Network Programming
- [Python Socket Programming](https://realpython.com/python-sockets/)
- [Threading in Python](https://docs.python.org/3/library/threading.html)

### Security Best Practices
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

## ✅ Grading Rubric (Self-Check)

| Component | Points | Criteria |
|-----------|--------|----------|
| **Crypto Implementation** | 40 | |
| - Modular arithmetic | 8 | Correct and efficient |
| - ElGamal encryption | 10 | Functional encrypt/decrypt |
| - ElGamal signatures | 12 | Functional sign/verify |
| - Prime generation | 10 | 2048-bit primes in reasonable time |
| **Protocol Implementation** | 35 | |
| - Phase 0 (Params) | 5 | Correct distribution |
| - Phase 1 (Mutual Auth) | 10 | Both parties authenticate |
| - Phase 2 (Session Key) | 10 | Correct derivation & HMAC |
| - Phase 3 (Group Key) | 10 | Broadcast functional |
| **Concurrency** | 10 | |
| - Multi-threading | 5 | Multiple drones simultaneous |
| - Thread safety | 5 | No race conditions |
| **Security** | 10 | |
| - Attack demos | 5 | All three working |
| - SECURITY.md | 5 | Clear explanations |
| **Documentation** | 5 | |
| - Code comments | 2 | Well-documented |
| - README.md | 3 | Complete benchmarks |

**Total: 100 points**

---

## 🎓 Learning Outcomes

By completing this assignment, you will:

1. ✅ Understand asymmetric cryptography internals
2. ✅ Implement secure authentication protocols
3. ✅ Handle concurrent network connections
4. ✅ Recognize and mitigate security attacks
5. ✅ Gain experience with real-world cryptographic systems

---

## 📞 Getting Help

If stuck:

1. **Re-read the assignment PDF** - Most answers are there
2. **Check your math** - ElGamal is mathematically precise
3. **Add debug prints** - See what values are being computed
4. **Test incrementally** - Don't write everything then test
5. **Ask on course forum** - But don't share code

---

## 🏁 Final Notes

### Do's
✅ Implement all cryptographic functions manually  
✅ Test each component independently  
✅ Add comprehensive error handling  
✅ Document complex algorithms  
✅ Start early - crypto debugging takes time  

### Don'ts
❌ Use high-level crypto libraries for ElGamal  
❌ Skip signature verification (security critical)  
❌ Ignore thread safety in MCC  
❌ Forget to validate timestamps  
❌ Copy code from online sources  

### Success Criteria
🎯 All three attacks demonstrate the vulnerabilities  
🎯 Multiple drones can connect simultaneously  
🎯 Broadcast reaches all authenticated drones  
🎯 2048-bit operations complete in reasonable time  
🎯 Code is well-documented and readable  

---

**Good luck with your implementation! 🚁🔐**

---

*Last Updated: February 5, 2026*