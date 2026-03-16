"""
Secure UAV Command-and-Control System
Drone Client Implementation

Connects to MCC and executes commands securely.
"""

import socket
import struct
import time
import sys
import random
import argparse
from crypto_utils import (
    generate_elgamal_keypair,
    ElGamalKey, elgamal_encrypt, elgamal_verify,
    hash_sha256, hash_sha256_int, hmac_sha256, aes_encrypt, aes_decrypt,
    int_to_bytes, int_to_bytes_variable, bytes_from_int_variable
)


# ============================================================================
# Drone: UAV Client Implementation
# ============================================================================

class Drone:
    """UAV Drone Client."""
    
    def __init__(self, drone_id, mcc_host='localhost', mcc_port=5555):
        """
        Initialize Drone Client.
        
        Args:
            drone_id: Unique identifier for this drone
            mcc_host: MCC server address
            mcc_port: MCC server port
        """
        self.drone_id = drone_id
        self.mcc_host = mcc_host
        self.mcc_port = mcc_port
        
        # Cryptographic state
        self.p = None
        self.g = None
        self.security_level = None
        self.mcc_public_key = None            # MCC's public key
        self.keypair = None                   # Drone's own keypair
        
        # Session state
        self.shared_secret = None             # KDi,MCC
        self.session_key = None               # SKDi,MCC
        self.group_key = None                 # GK for broadcasts
        self.authenticated = False
        
        # Nonces and timestamps
        self.my_nonce = None                  # RNi
        self.my_timestamp = None              # TSi
        self.mcc_nonce = None                 # RNMCC
        self.mcc_timestamp = None             # TSMCC
        
        # Socket
        self.socket = None
        self.running = False
        
        print(f"[{self.drone_id}] Initialized")
    
    def recv_message(self):
        """Receive a length-prefixed message from socket."""
        length_data = b''
        while len(length_data) < 4:
            chunk = self.socket.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk
        msg_len = struct.unpack('>I', length_data)[0]
        
        data = b''
        while len(data) < msg_len:
            chunk = self.socket.recv(min(8192, msg_len - len(data)))
            if not chunk:
                return None
            data += chunk
        return data
    
    # ========================================================================
    # PHASE 0: Receive Cryptographic Parameters from MCC
    # ========================================================================
    
    def receive_phase0_params(self):
        """
        Phase 0: Receive and validate crypto parameters from MCC.
        
        Validates:
        - Security level >= 2048
        - Prime p has correct bit length
        - Signature verification
        """
        try:
            # Receive length-prefixed OPCODE 10 message
            data = self.recv_message()
            if not data:
                print(f"[{self.drone_id}] No data received in Phase 0")
                return False
            
            if data[0] != 10:
                print(f"[{self.drone_id}] Invalid opcode in Phase 0: {data[0]}")
                return False
            
            offset = 1
            
            # Parse p
            self.p, offset = bytes_from_int_variable(data, offset)
            
            # Parse g
            self.g, offset = bytes_from_int_variable(data, offset)
            
            # Parse security level
            self.security_level = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            
            # Parse timestamp
            ts0 = struct.unpack('>Q', data[offset:offset+8])[0]
            offset += 8
            
            # Parse MCC ID
            idmcc_int, offset = bytes_from_int_variable(data, offset)
            
            # Parse MCC's public key Y
            mcc_y, offset = bytes_from_int_variable(data, offset)
            
            # Parse signature (r, s)
            sig_r, offset = bytes_from_int_variable(data, offset)
            sig_s, offset = bytes_from_int_variable(data, offset)
            signature = (sig_r, sig_s)
            
            # SECURITY CHECK 1: Validate security level meets minimum safety requirement
            MIN_SECURITY_LEVEL = 2048
            if self.security_level < MIN_SECURITY_LEVEL:
                print(f"[{self.drone_id}] Phase 0: REJECTED - Security level too weak")
                print(f"[{self.drone_id}]   Claimed SL: {self.security_level} bits")
                print(f"[{self.drone_id}]   Required: >= {MIN_SECURITY_LEVEL} bits")
                print(f"[{self.drone_id}]   TAMPER DETECTED: MitM may be forcing weak parameters")
                return False
            
            # SECURITY CHECK 2: Validate prime bit length matches claimed security level
            # Defense against MitM replacing prime with weak value while claiming high SL
            actual_bits = self.p.bit_length()
            claimed_bits = self.security_level
            
            if abs(actual_bits - claimed_bits) > 2:
                print(f"[{self.drone_id}] Phase 0: REJECTED - Prime/SL inconsistency")
                print(f"[{self.drone_id}]   Actual prime length: {actual_bits} bits")
                print(f"[{self.drone_id}]   Claimed SL: {claimed_bits} bits")
                print(f"[{self.drone_id}]   Mismatch: {abs(actual_bits - claimed_bits)} bits")
                print(f"[{self.drone_id}]   TAMPER DETECTED: MitM modified prime parameter")
                print(f"[{self.drone_id}]   Connection will be CLOSED for security")
                return False
            
            # Create MCC's public key from received Y
            self.mcc_public_key = ElGamalKey(self.p, self.g, y=mcc_y)
            
            # SECURITY CHECK 3: Verify MCC's signature on Phase 0 parameters
            # Reconstructs the exact message MCC signed and validates signature
            # If signature fails, parameters were tampered during transmission
            msg_phase0 = int_to_bytes_variable(self.p)
            msg_phase0 += int_to_bytes_variable(self.g)
            msg_phase0 += struct.pack('>I', self.security_level)
            msg_phase0 += struct.pack('>Q', ts0)
            msg_phase0 += int_to_bytes_variable(idmcc_int)
            msg_phase0 += int_to_bytes_variable(mcc_y)
            
            msg_hash = hash_sha256_int(msg_phase0)
            if not elgamal_verify(msg_hash, signature, self.mcc_public_key):
                print(f"[{self.drone_id}] Phase 0: REJECTED - Signature verification FAILED")
                print(f"[{self.drone_id}]   TAMPER DETECTED: Parameters modified by MitM")
                print(f"[{self.drone_id}]   Connection will be CLOSED for security")
                return False
            
            print(f"[{self.drone_id}] Phase 0: ✓ ALL SECURITY CHECKS PASSED")
            print(f"[{self.drone_id}]   ✓ Security level adequate ({self.security_level} >= 2048)")
            print(f"[{self.drone_id}]   ✓ Prime length consistent ({actual_bits} ≈ {claimed_bits})")
            print(f"[{self.drone_id}]   ✓ MCC signature valid (no tampering)")
            print(f"[{self.drone_id}] Phase 0: Parameters accepted")
            print(f"[{self.drone_id}]   - Prime: {actual_bits} bits")
            print(f"[{self.drone_id}]   - Generator: {self.g}")
            print(f"[{self.drone_id}]   - Security Level: {self.security_level}")
            
            # Generate drone's own ElGamal keypair
            print(f"[{self.drone_id}] Generating own key pair...")
            self.keypair = generate_elgamal_keypair(self.p, self.g)
            print(f"[{self.drone_id}] Key pair generated")
            print(f"[{self.drone_id}]   - Public Key: {self.keypair.y}")
            
            return True
            
        except Exception as e:
            print(f"[{self.drone_id}] Phase 0 Error: {e}")
            return False
    
    # ========================================================================
    # PHASE 1A: Send Authentication Request to MCC
    # ========================================================================
    
    def send_phase1a_auth_request(self):
        """
        Phase 1A: Send authentication request to MCC.
        
        Sends:
        - OPCODE: 20 (1 byte)
        - TSi: Timestamp (8 bytes)
        - RNi: Nonce (32 bytes)
        - IDDi: Drone ID (variable)
        - Ci: Encrypted KDi,MCC (variable)
        - Signature: (variable)
        """
        try:
            # Generate shared secret
            self.shared_secret = random.randint(100, self.p - 100)
            
            # Generate timestamp
            self.my_timestamp = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
            
            # Generate nonce (32 bytes)
            nonce_int = random.randint(0, 2**256 - 1)
            self.my_nonce = int_to_bytes(nonce_int, 32)
            
            # Prepare message
            tsi = self.my_timestamp
            rni = self.my_nonce
            iddi = self.drone_id.encode('utf-8') if isinstance(self.drone_id, str) else self.drone_id
            
            # Encrypt shared secret with MCC's public key
            ci = elgamal_encrypt(self.shared_secret, self.mcc_public_key)
            
            # Create message M1A = TSi || RNi || IDDi || Ci
            msg_1a = struct.pack('>Q', tsi)
            msg_1a += rni
            msg_1a += struct.pack('>I', len(iddi)) + iddi
            msg_1a += int_to_bytes_variable(ci[0]) + int_to_bytes_variable(ci[1])
            
            # Sign message with drone's private key
            msg_hash = hash_sha256_int(msg_1a) % (self.p - 1)
            from crypto_utils import elgamal_sign
            signature = elgamal_sign(msg_hash, self.keypair)
            
            # Pack full message
            full_msg = struct.pack('B', 20)  # OPCODE 20
            full_msg += msg_1a
            full_msg += int_to_bytes_variable(signature[0]) + int_to_bytes_variable(signature[1])
            
            # Send with length prefix
            length_prefix = struct.pack('>I', len(full_msg))
            self.socket.sendall(length_prefix + full_msg)
            print(f"[{self.drone_id}] Phase 1A: Sent authentication request")
            
            return True
            
        except Exception as e:
            print(f"[{self.drone_id}] Phase 1A Error: {e}")
            return False
    
    # ========================================================================
    # PHASE 1B: Receive and Process MCC Response
    # ========================================================================
    
    def receive_phase1b_response(self):
        """
        Phase 1B: Receive and validate MCC authentication response.
        
        Receives:
        - OPCODE: 30 (1 byte)
        - TSMCC: MCC Timestamp (8 bytes)
        - RNMCC: MCC Nonce (32 bytes)
        - IDMCC: MCC ID (variable)
        - CMCC: Encrypted KDi,MCC (variable)
        - Signature: (variable)
        """
        try:
            # Receive length-prefixed message
            data = self.recv_message()
            if not data:
                print(f"[{self.drone_id}] No data received in Phase 1B")
                return False
            
            if data[0] != 30:
                print(f"[{self.drone_id}] Invalid opcode in Phase 1B: {data[0]}")
                return False
            
            offset = 1
            
            # Parse MCC timestamp
            self.mcc_timestamp = struct.unpack('>Q', data[offset:offset+8])[0]
            offset += 8
            
            # Parse MCC nonce
            self.mcc_nonce = data[offset:offset+32]
            offset += 32
            
            # Parse MCC ID
            idmcc_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            idmcc = data[offset:offset+idmcc_len]
            offset += idmcc_len
            
            # Parse HMAC proof (32 bytes)
            received_proof = data[offset:offset+32]
            offset += 32
            
            # Parse signature
            sig_r, offset = bytes_from_int_variable(data, offset)
            sig_s, offset = bytes_from_int_variable(data, offset)
            
            # Verify timestamp freshness
            current_time = int(time.time() * 1000)
            time_diff = (current_time - self.mcc_timestamp) / 1000.0
            if time_diff > 30 or time_diff < -5:
                print(f"[{self.drone_id}] Phase 1B: Timestamp too old/future")
                return False
            
            # Verify MCC's proof of shared secret knowledge
            secret_bytes = int_to_bytes(self.shared_secret)
            expected_proof = hmac_sha256(hash_sha256(secret_bytes), idmcc + struct.pack('>Q', self.mcc_timestamp))
            if received_proof != expected_proof:
                print(f"[{self.drone_id}] Phase 1B: MCC failed proof of shared secret!")
                return False
            
            print(f"[{self.drone_id}] Phase 1B: Received MCC response")
            print(f"[{self.drone_id}] Phase 1B: MCC proved knowledge of shared secret")
            return True
            
        except Exception as e:
            print(f"[{self.drone_id}] Phase 1B Error: {e}")
            return False
    
    # ========================================================================
    # PHASE 2: Session Key Confirmation
    # ========================================================================
    
    def send_phase2_confirmation(self):
        """
        Phase 2: Derive session key and send confirmation.
        
        Derives:
        SKDi,MCC = SHA256(KDi,MCC || TSi || TSMCC || RNi || RNMCC)
        
        Sends:
        - OPCODE: 40 (1 byte)
        - HMAC-SHA256(SKDi,MCC, IDDi || TSfinal) (32 bytes)
        """
        try:
            # Derive session key
            # Convert shared secret to bytes (variable length, then hash it)
            secret_bytes = int_to_bytes(self.shared_secret)
            secret_hash = hash_sha256(secret_bytes)
            
            sk_material = secret_hash
            sk_material += struct.pack('>Q', self.my_timestamp)
            sk_material += struct.pack('>Q', self.mcc_timestamp)
            sk_material += self.my_nonce
            sk_material += self.mcc_nonce
            
            self.session_key = hash_sha256(sk_material)
            
            # Create final timestamp and include it in the message
            final_ts = struct.pack('>Q', int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)
            hmac_data = self.drone_id.encode('utf-8') if isinstance(self.drone_id, str) else self.drone_id
            hmac_data += final_ts
            
            # Compute HMAC
            hmac_value = hmac_sha256(self.session_key, hmac_data)
            
            # Pack message: OPCODE || TSfinal || HMAC
            full_msg = struct.pack('B', 40)  # OPCODE 40
            full_msg += final_ts              # 8 bytes - so MCC can compute same HMAC
            full_msg += hmac_value            # 32 bytes
            
            # Send with length prefix
            length_prefix = struct.pack('>I', len(full_msg))
            self.socket.sendall(length_prefix + full_msg)
            print(f"[{self.drone_id}] Phase 2: Sent session key confirmation")
            print(f"[{self.drone_id}]   Session Key: {self.session_key.hex()[:32]}...")
            
            return True
            
        except Exception as e:
            print(f"[{self.drone_id}] Phase 2 Error: {e}")
            return False
    
    def wait_for_confirmation(self):
        """Wait for MCC's final confirmation."""
        try:
            data = self.socket.recv(1024)
            if not data:
                return False
            
            opcode = struct.unpack('B', data[0:1])[0]
            
            if opcode == 50:  # SUCCESS
                self.authenticated = True
                print(f"[{self.drone_id}] Authentication successful!")
                return True
            elif opcode == 60:  # MISMATCH
                print(f"[{self.drone_id}] Authentication failed - key mismatch!")
                return False
            else:
                print(f"[{self.drone_id}] Unexpected response: {opcode}")
                return False
            
        except Exception as e:
            print(f"[{self.drone_id}] Wait for confirmation error: {e}")
            return False
    
    # ========================================================================
    # PHASE 3: Receive Group Key and Commands
    # ========================================================================
    
    def receive_group_key(self, data):
        """
        Phase 3: Receive and decrypt group key.
        
        Receives:
        - OPCODE: 70 (1 byte)
        - IV: 16 bytes
        - Encrypted GK
        """
        try:
            iv = data[1:17]
            encrypted_gk = data[17:]
            
            # Decrypt using session key
            self.group_key = aes_decrypt(self.session_key, iv, encrypted_gk)
            print(f"[{self.drone_id}] Received Group Key: {self.group_key.hex()[:32]}...")
            
        except Exception as e:
            print(f"[{self.drone_id}] Error receiving group key: {e}")
    
    def receive_broadcast_command(self, data):
        """
        Receive and process broadcast command.
        
        Receives:
        - OPCODE: 80 (1 byte)
        - IV: 16 bytes
        - Encrypted command
        - HMAC tag: 32 bytes
        """
        try:
            if self.group_key is None:
                print(f"[{self.drone_id}] No group key received yet")
                return
            
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
            
        except Exception as e:
            print(f"[{self.drone_id}] Error receiving broadcast: {e}")
    
    def execute_command(self, command):
        """Execute a received command (simulation)."""
        cmd_lower = command.lower().strip()
        
        if cmd_lower == "return_to_base":
            print(f"[{self.drone_id}] >> Executing: Returning to base...")
        elif cmd_lower == "land":
            print(f"[{self.drone_id}] >> Executing: Landing...")
        elif cmd_lower == "takeoff":
            print(f"[{self.drone_id}] >> Executing: Taking off...")
        elif cmd_lower == "hover":
            print(f"[{self.drone_id}] >> Executing: Hovering...")
        elif cmd_lower.startswith("move "):
            direction = cmd_lower[5:]
            print(f"[{self.drone_id}] >> Executing: Moving {direction}...")
        else:
            print(f"[{self.drone_id}] >> Executing: {command}")
    
    # ========================================================================
    # Graceful Disconnect Signal
    # ========================================================================
    
    def send_disconnect_signal(self):
        """
        Send OPCODE 95 (DISCONNECT) to MCC before closing socket.
        This allows MCC to immediately clean up this drone's session,
        rather than waiting for socket EOF detection.
        """
        if self.socket and self.authenticated:
            try:
                # OPCODE 95: DISCONNECT signal with drone ID
                drone_id_bytes = self.drone_id.encode('utf-8') if isinstance(self.drone_id, str) else self.drone_id
                msg = struct.pack('B', 95)  # OPCODE 95
                msg += struct.pack('>I', len(drone_id_bytes))
                msg += drone_id_bytes
                self.socket.sendall(msg)
                print(f"[{self.drone_id}] Sent disconnect signal to MCC")
            except Exception as e:
                print(f"[{self.drone_id}] Could not send disconnect signal: {e}")
    
    # ========================================================================
    # Main Connection Routine
    # ========================================================================
    
    def connect_to_mcc(self):
        """
        Main connection routine.
        
        Flow:
        1. Connect to MCC
        2. Receive Phase 0 parameters
        3. Send Phase 1A authentication
        4. Receive Phase 1B response
        5. Send Phase 2 confirmation
        6. Enter listening mode for commands
        """
        try:
            # Connect to MCC
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.mcc_host, self.mcc_port))
            print(f"[{self.drone_id}] Connected to MCC at {self.mcc_host}:{self.mcc_port}")
            
            # Phase 0: Receive parameters
            if not self.receive_phase0_params():
                print(f"[{self.drone_id}] Phase 0 FAILED - Aborting connection")
                print(f"[{self.drone_id}] Connection CLOSED for security (possible MitM attack)")
                return False
            
            time.sleep(0.1)
            
            # Phase 1A: Send authentication request
            if not self.send_phase1a_auth_request():
                print(f"[{self.drone_id}] Phase 1A failed")
                return False
            
            time.sleep(0.1)
            
            # Phase 1B: Receive MCC response
            if not self.receive_phase1b_response():
                print(f"[{self.drone_id}] Phase 1B failed")
                return False
            
            time.sleep(0.1)
            
            # Phase 2: Send confirmation
            if not self.send_phase2_confirmation():
                print(f"[{self.drone_id}] Phase 2 failed")
                return False
            
            # Wait for auth confirmation
            if not self.wait_for_confirmation():
                print(f"[{self.drone_id}] Auth confirmation failed")
                return False
            
            # Phase 3: Listen for group key and commands
            print(f"[{self.drone_id}] Entering listening mode...")
            self.running = True
            
            while self.running and self.authenticated:
                try:
                    # Receive message with timeout
                    self.socket.settimeout(5.0)
                    data = self.socket.recv(4096)
                    
                    if not data:
                        print(f"[{self.drone_id}] Connection closed by MCC")
                        break
                    
                    opcode = struct.unpack('B', data[0:1])[0]
                    
                    if opcode == 70:  # GROUP_KEY
                        self.receive_group_key(data)
                    
                    elif opcode == 80:  # GROUP_CMD
                        self.receive_broadcast_command(data)
                    
                    elif opcode == 90:  # SHUTDOWN
                        print(f"[{self.drone_id}] \n" + "="*60)
                        print(f"[{self.drone_id}] SHUTDOWN SIGNAL RECEIVED FROM MCC")
                        print(f"[{self.drone_id}] " + "="*60)
                        self.running = False
                        break
                    
                    else:
                        print(f"[{self.drone_id}] Unknown opcode: {opcode}")
                
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[{self.drone_id}] Error in listening mode: {e}")
                    break
            
            return True
            
        except Exception as e:
            print(f"[{self.drone_id}] Connection error: {e}")
            return False
        
        finally:
            self.running = False
            # Send graceful disconnect signal before closing socket
            self.send_disconnect_signal()
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            print(f"[{self.drone_id}] Disconnected from MCC")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="UAV Drone Client")
    parser.add_argument('--id', dest='drone_id', required=True, help='Drone ID')
    parser.add_argument('--mcc-host', default='localhost', help='MCC host address')
    parser.add_argument('--mcc-port', type=int, default=8001, help='MCC port')
    
    args = parser.parse_args()
    
    # Create and connect drone
    drone = Drone(args.drone_id, args.mcc_host, args.mcc_port)
    
    try:
        success = drone.connect_to_mcc()
        if success:
            print(f"[{args.drone_id}] Connection completed successfully")
        else:
            print(f"[{args.drone_id}] Connection failed")
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n[{args.drone_id}] Interrupted")
        drone.running = False
    finally:
        # Ensure clean exit
        print(f"[{args.drone_id}] Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
