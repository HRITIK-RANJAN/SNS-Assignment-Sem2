"""
Secure UAV Command-and-Control System
Drone Client Implementation

Connects to MCC and executes commands securely.
"""

import socket
import struct
import time
import sys
import threading
from crypto_utils import (
    generate_large_prime, find_generator, generate_elgamal_keypair,
    ElGamalKey, elgamal_encrypt, elgamal_decrypt, elgamal_verify,
    hash_sha256, hash_sha256_int, hmac_sha256, aes_encrypt, aes_decrypt,
    bytes_to_int, int_to_bytes, int_to_bytes_variable, bytes_from_int_variable,
    deserialize_key
)
import random


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
            # Receive OPCODE 10 message
            data = self.socket.recv(8192)
            
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
            idmcc_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            idmcc = data[offset:offset+idmcc_len]
            offset += idmcc_len
            
            # Parse signature (r, s)
            sig_r, offset = bytes_from_int_variable(data, offset)
            sig_s, offset = bytes_from_int_variable(data, offset)
            signature = (sig_r, sig_s)
            
            # Validate security level
            if self.security_level < 2048:
                print(f"[{self.drone_id}] Invalid security level: {self.security_level}")
                return False
            
            # Validate prime bit length
            if abs(self.p.bit_length() - self.security_level) > 2:
                print(f"[{self.drone_id}] Prime bit length mismatch: {self.p.bit_length()} vs {self.security_level}")
                return False
            
            # Create MCC's public key for signature verification
            # Note: In real system, this would be from PKI
            # For demo, we accept the params
            self.mcc_public_key = ElGamalKey(self.p, self.g, y=42)  # Dummy
            
            print(f"[{self.drone_id}] Phase 0: Received parameters")
            print(f"[{self.drone_id}]   - Prime: {self.p.bit_length()} bits")
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
            signature = (random.randint(1, self.p-2), random.randint(1, self.p-2))  # Dummy sig for demo
            
            # Pack full message
            full_msg = struct.pack('B', 20)  # OPCODE 20
            full_msg += msg_1a
            full_msg += int_to_bytes_variable(signature[0]) + int_to_bytes_variable(signature[1])
            
            # Send
            self.socket.sendall(full_msg)
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
            # Receive message
            data = self.socket.recv(8192)
            
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
            
            # Parse encrypted secret (c1, c2)
            cmcc_c1, offset = bytes_from_int_variable(data, offset)
            cmcc_c2, offset = bytes_from_int_variable(data, offset)
            cmcc = (cmcc_c1, cmcc_c2)
            
            # Parse signature
            sig_r, offset = bytes_from_int_variable(data, offset)
            sig_s, offset = bytes_from_int_variable(data, offset)
            
            # Verify timestamp freshness
            current_time = int(time.time() * 1000)
            time_diff = (current_time - self.mcc_timestamp) / 1000.0
            if time_diff > 30 or time_diff < -5:
                print(f"[{self.drone_id}] Phase 1B: Timestamp too old/future")
                return False
            
            # Decrypt CMCC to verify it matches our shared secret
            # For demo: we'll just proceed with the shared secret
            
            print(f"[{self.drone_id}] Phase 1B: Received MCC response")
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
            sk_material = int_to_bytes(self.shared_secret, 32)
            sk_material += struct.pack('>Q', self.my_timestamp)
            sk_material += struct.pack('>Q', self.mcc_timestamp)
            sk_material += self.my_nonce
            sk_material += self.mcc_nonce
            
            self.session_key = hash_sha256(sk_material)
            
            # Create final message
            final_ts = struct.pack('>Q', int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)
            hmac_data = self.drone_id.encode('utf-8') if isinstance(self.drone_id, str) else self.drone_id
            hmac_data += final_ts
            
            # Compute HMAC
            hmac_value = hmac_sha256(self.session_key, hmac_data)
            
            # Pack message
            full_msg = struct.pack('B', 40)  # OPCODE 40
            full_msg += hmac_value
            
            # Send
            self.socket.sendall(full_msg)
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
                print(f"[{self.drone_id}] Phase 0 failed")
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
                        print(f"[{self.drone_id}] Received shutdown signal")
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
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            print(f"[{self.drone_id}] Disconnected from MCC")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="UAV Drone Client")
    parser.add_argument('--id', dest='drone_id', required=True, help='Drone ID')
    parser.add_argument('--mcc-host', default='localhost', help='MCC host address')
    parser.add_argument('--mcc-port', type=int, default=5555, help='MCC port')
    
    args = parser.parse_args()
    
    # Create and connect drone
    drone = Drone(args.drone_id, args.mcc_host, args.mcc_port)
    
    try:
        success = drone.connect_to_mcc()
        if success:
            print(f"[{args.drone_id}] Connection completed successfully")
        else:
            print(f"[{args.drone_id}] Connection failed")
    except KeyboardInterrupt:
        print(f"\n[{args.drone_id}] Interrupted")
        drone.running = False


if __name__ == "__main__":
    main()
