# Quick Start Guide - Secure UAV C2 System

## Installation

### 1. Install Dependencies

```bash
cd /home/learning/Desktop/SEM2/SNS/ASSIGNMENTS/A2
pip install -r requirements.txt
```

### 2. Verify Installation

```bash
python crypto_utils.py
```

Expected output:
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

## Running the System

### Terminal 1: Start MCC Server

```bash
python3 mcc.py --host localhost --port 8000 --security-level 2048
```

Output:
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
```

### Terminal 2: Start Drone 1

```bash
python3 drone.py --id D001 --mcc-host localhost --mcc-port 8000
```

Output:
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

### Terminal 3: Start Drone 2 (Optional)

```bash
python3 drone.py --id D002 --mcc-host localhost --mcc-port 8000
```

### Terminal 1 (MCC): Execute Commands

```
MCC> list
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

MCC> broadcast RETURN_TO_BASE
[MCC] Broadcasting command: RETURN_TO_BASE
[MCC] Generated Group Key: a1b2c3d4e5f6...
[MCC] Sent GK to D001
[MCC] Sent GK to D002
[MCC] Broadcast to D001
[MCC] Broadcast to D002
```

### Drone Terminals: See Commands

```
[D001] Received Group Key: a1b2c3d4e5f6...
[D001] Received command: RETURN_TO_BASE
[D001] >> Executing: Returning to base...

[D002] Received Group Key: a1b2c3d4e5f6...
[D002] Received command: RETURN_TO_BASE
[D002] >> Executing: Returning to base...
```

### Shutdown

In MCC terminal:
```
MCC> shutdown
[MCC] Initiating shutdown...
```

---

## Running Security Attack Demonstrations

### Prerequisites

1. MCC server running (Terminal 1)
2. At least 1 drone connected (Terminal 2)

### Execute Attacks

In a new terminal:

```bash
python3 attacks.py --mcc-host localhost --mcc-port 8000
```

### Expected Output

```
======================================================================
SECURE UAV C2 SYSTEM - SECURITY ATTACK DEMONSTRATIONS
======================================================================
Target MCC: localhost:5555
======================================================================

Attempting Attack 1: Replay Attack...
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

Attempting Attack 2: Man-in-the-Middle Attack...
[MItM ATTACK] Attempting to set up proxy attack...
[MItM ATTACK] Step 1: Intercept MCC -> Drone connection
[MItM ATTACK] Step 2: Receive Phase 0 parameters from MCC
[MItM ATTACK] Step 3: Modify parameters to weaken encryption
[MItM ATTACK] ✓ Cannot re-sign tampered parameters!
[MItM ATTACK] ✓ Drone will reject due to signature failure!
[MItM ATTACK]   Result: ATTACK PREVENTED
======================================================================

[... more attacks ...]

======================================================================
ATTACK DEMONSTRATIONS COMPLETED
======================================================================
Summary: All attacks were successfully prevented by:
  1. Timestamp validation
  2. Digital signature verification
  3. HMAC-based message authentication
  4. Mutual authentication protocols
======================================================================
```

---

## Common Commands in MCC

### List Drones
```
MCC> list
```
Shows all authenticated drones.

### Broadcast Command
```
MCC> broadcast TAKEOFF
MCC> broadcast LAND
MCC> broadcast HOVER
MCC> broadcast RETURN_TO_BASE
```

### Check Status
```
MCC> status
```
Shows server status and connection count.

### Shutdown
```
MCC> shutdown
```
Gracefully closes all connections.

---

## File Descriptions

| File | Purpose |
|------|---------|
| `crypto_utils.py` | Core cryptographic functions (ElGamal, AES, HMAC, etc.) |
| `mcc.py` | Mission Control Center server |
| `drone.py` | UAV Drone client |
| `attacks.py` | Security attack demonstrations |
| `SECURITY.md` | Detailed security analysis |
| `requirements.txt` | Python package dependencies |
| `README.md` | Implementation guide |

---

## Troubleshooting

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
