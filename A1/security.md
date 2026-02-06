# Security Analysis: Secure Client-Server Protocol

## Threat Model

This document analyzes the security properties of the implemented protocol against active network attackers capable of intercepting, modifying, replaying, or dropping packets in transit between clients and server.

## Cryptographic Foundations

### Encryption
- **Algorithm**: AES-128 in CBC mode
- **Key Size**: 128 bits (16 bytes)
- **IV Generation**: Fresh random 16-byte IV per packet
- **Purpose**: Provides confidentiality against eavesdropping

### Integrity and Authentication
- **Algorithm**: HMAC-SHA256
- **Key Size**: 256 bits (32 bytes)
- **Coverage**: Header + IV + Ciphertext
- **Purpose**: Ensures message integrity and sender authenticity

### Key Derivation and Evolution
- **Algorithm**: SHA-256
- **Purpose**: Derives session keys and implements forward secrecy through ratcheting

## Attack Vectors and Defenses

### 1. Replay Attacks

**Attack Scenario**: Attacker captures a valid packet and retransmits it to cause duplicate actions.

**Defense Mechanism**:
- Strict round number validation in packet headers
- Server maintains per-client round counters
- Any packet with incorrect round number triggers immediate connection termination

**Implementation**:
```python
if rcv_round != self.round:
    raise DesyncError(f"Round mismatch: Expected {self.round}, Got {rcv_round}")
```

### 2. Message Tampering

**Attack Scenario**: Attacker modifies packet contents to alter the intended action.

**Defense Mechanism**:
- HMAC-SHA256 covers all packet components (header, IV, ciphertext)
- Any modification invalidates the HMAC tag
- Failed HMAC verification terminates the connection

**Implementation**:
```python
expected_mac = compute_hmac(key_mac, header + iv + ciphertext)
if expected_mac != mac_tag:
    raise HMACError("HMAC Verification Failed!")
```

### 3. Message Reordering and Desynchronization

**Attack Scenario**: Attacker reorders packets or drops them to break protocol synchronization.

**Defense Mechanism**:
- Enforced sequential round progression
- Key ratcheting ensures keys evolve predictably
- Out-of-order packets fail round validation or decryption

**Implementation**:
- Round counters incremented only after successful exchanges
- Keys ratchet using: `new_key = SHA256(old_key + message_data)`

### 4. Reflection Attacks

**Attack Scenario**: Attacker captures server responses and sends them back to the server.

**Defense Mechanism**:
- Directional flags in packet headers (DIR_C2S = 0, DIR_S2C = 1)
- Server rejects packets with incorrect direction flags

**Implementation**:
```python
if rcv_dir != expected_direction:
    raise ProtocolError(f"Wrong direction: Expected {expected_direction}, Got {rcv_dir}")
```

### 5. Forward Secrecy Compromise

**Attack Scenario**: Attacker records traffic and later compromises current session keys.

**Defense Mechanism**:
- Per-message key ratcheting destroys old keys
- SHA-256 one-way function prevents key recovery
- Compromised current keys don't reveal past keys

### 6. Man-in-the-Middle Attacks

**Attack Scenario**: Attacker positions between client and server to intercept/modify traffic.

**Defense Mechanism**:
- Combined encryption + HMAC + direction validation
- Any MITM modification fails cryptographic checks
- Connection termination on security violations

### 7. Denial of Service

**Attack Scenario**: Attacker floods server with malformed packets.

**Defense Mechanism**:
- Fail-fast error handling terminates invalid connections
- Limited client concurrency (100 max via key database)
- No retry logic prevents abuse amplification

## Key Management Architecture

### Initial Key Derivation
- Master key: `SHA256("basekey" + client_id)`
- Encryption key: First 16 bytes of master key
- MAC key: Full 32 bytes of master key

### Session Key Separation
- Client-to-Server (C2S) keys: For client-sent packets
- Server-to-Client (S2C) keys: For server-sent packets
- Independent evolution for each direction

### Key Ratcheting Process
- After sending: Update sending keys with message data
- After receiving: Update receiving keys with received data
- Ensures forward secrecy and prevents key reuse

## Protocol State Machine

### States and Transitions
1. **HELLO Phase** (Round 0): Initial handshake
2. **CHALLENGE Phase** (Round 0): Server authentication
3. **DATA Exchange** (Rounds 1+): Secure communication loop

### Error Handling
- All security exceptions inherit from `ProtocolError`
- Immediate connection termination on violations
- No recovery attempts to prevent exploitation

## Data Aggregation Security

### Aggregation Process
- Per-client: Sum numeric inputs or use byte length
- Global: Product across all clients in current round
- Thread-safe implementation with locks

### Security Considerations
- Aggregation uses evolved keys for responses
- No injection vulnerabilities in data processing
- Race condition protection in multi-client scenarios

## Attack Simulation Framework

The `attacks.py` (MITM proxy) implements controlled attack scenarios:

- **Replay**: Duplicates packets to test round validation
- **Tamper**: Corrupts ciphertext to test HMAC integrity
- **Drop**: Discards packets to test desynchronization handling
- **Reflection**: Redirects server responses to test direction validation

## Limitations and Assumptions

### Trust Assumptions
- Secure initial key distribution (pre-shared keys)
- No insider threats or key compromise at endpoints
- Trusted client/server software implementations

### Protocol Limitations
- Symmetric cryptography only (no public key operations)
- No certificate-based authentication
- Fixed maximum client limit (100)
- No protection against passive eavesdropping (beyond encryption)

### Operational Constraints
- Requires manual key management
- No automatic key rotation or revocation
- Vulnerable to DoS if key space exhausted

## Security Testing Methodology

1. **Unit Testing**: Individual cryptographic functions
2. **Integration Testing**: Full protocol flows
3. **Attack Simulation**: MITM proxy with controlled attacks
4. **Concurrency Testing**: Multi-client scenarios

## Compliance and Standards

- Uses FIPS-approved cryptographic algorithms
- Implements standard security practices (IV randomization, HMAC)
- Follows fail-safe security design principles