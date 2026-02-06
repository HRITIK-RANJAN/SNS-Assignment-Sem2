"""
Secure UAV Command-and-Control System
Mission Control Center (MCC) - Server Implementation

Manages multiple drone connections with secure authentication and group key distribution.
"""

import socket
import threading
import struct
import time
import sys
from datetime import datetime
from crypto_utils import (
    generate_large_prime, find_generator, generate_elgamal_keypair,
    ElGamalKey, elgamal_encrypt, elgamal_decrypt, elgamal_sign, 
    hash_sha256, hash_sha256_int, hmac_sha256, aes_encrypt, aes_decrypt,
    bytes_to_int, int_to_bytes, int_to_bytes_variable, bytes_from_int_variable,
    serialize_key, deserialize_key
)


# ============================================================================
# DroneSession: Represents a connected drone's session state
# ============================================================================

class DroneSession:
    """Represents a connected drone's session state."""
    
    def __init__(self, drone_id, client_socket, address):
        """
        Initialize drone session.
        
        Args:
            drone_id: Unique identifier for drone
            client_socket: Connected socket
            address: Client address (host, port)
        """
        self.drone_id = drone_id
        self.socket = client_socket
        self.address = address
        self.drone_public_key = None      # Received from drone
        self.shared_secret = None         # KDi,MCC
        self.session_key = None           # SKDi,MCC (32 bytes)
        self.authenticated = False
        self.timestamp_auth = None
        self.nonce_drone = None           # RNi
        self.nonce_mcc = None             # RNMCC
        self.timestamp_drone = None       # TSi
        self.timestamp_mcc = None         # TSMCC
        self.lock = threading.Lock()


# ============================================================================
# MissionControlCenter: Main server class
# ============================================================================

class MissionControlCenter:
    """Mission Control Center Server."""
    
    def __init__(self, host='localhost', port=5555, security_level=2048):
        """
        Initialize MCC Server.
        
        Args:
            host: Bind address
            port: Listen port
            security_level: Bit length for prime (2048 or 3072)
        """
        self.host = host
        self.port = port
        self.security_level = security_level
        
        print(f"[MCC] Initializing with security level {security_level}...")
        
        # Generate MCC's ElGamal parameters and keys
        print(f"[MCC] Generating large prime ({security_level} bits)...")
        self.p = generate_large_prime(security_level)
        print(f"[MCC] Prime generated: {self.p.bit_length()} bits")
        
        print("[MCC] Finding generator...")
        self.g = find_generator(self.p)
        print(f"[MCC] Generator found: {self.g}")
        
        print("[MCC] Generating MCC key pair...")
        self.keypair = generate_elgamal_keypair(self.p, self.g)
        self.keypair.sl = security_level
        print(f"[MCC] MCC Public Key Y: {self.keypair.y}")
        
        # Drone registry
        self.drones = {}                  # {drone_id: DroneSession}
        self.drones_lock = threading.Lock()
        
        # Server socket
        self.server_socket = None
        self.running = False
        self.threads = []
        
        print(f"[MCC] Initialized successfully")
    
    # ========================================================================
    # PHASE 0: Send Cryptographic Parameters
    # ========================================================================
    
    def send_phase0_params(self, client_socket):
        """
        Phase 0: Send crypto parameters to drone.
        
        Message Structure:
        - OPCODE: 10 (1 byte)
        - p (variable length with length prefix)
        - g (variable length with length prefix)
        - SL: Security level (4 bytes)
        - TS0: Timestamp (8 bytes)
        - IDMCC: MCC ID (variable length with length prefix)
        - Signature (variable length with length prefix)
        """
        try:
            # Prepare message M0 = p || g || SL || TS0 || IDMCC
            ts0 = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF  # 8 bytes
            idmcc = b"MCC_PRIMARY"
            
            # Create message bytes
            msg_data = int_to_bytes_variable(self.p)
            msg_data += int_to_bytes_variable(self.g)
            msg_data += struct.pack('>I', self.security_level)
            msg_data += struct.pack('>Q', ts0)
            msg_data += int_to_bytes_variable(bytes_to_int(idmcc))
            
            # Sign message
            msg_hash = hash_sha256_int(msg_data) % (self.p - 1)
            signature = elgamal_sign(msg_hash, self.keypair)
            sig_data = int_to_bytes_variable(signature[0])
            sig_data += int_to_bytes_variable(signature[1])
            
            # Pack full message
            full_msg = struct.pack('B', 10)  # OPCODE 10
            full_msg += msg_data
            full_msg += sig_data
            
            # Send
            client_socket.sendall(full_msg)
            print(f"[MCC] Phase 0: Sent parameters to client")
            
        except Exception as e:
            print(f"[MCC] Phase 0 Error: {e}")
            raise
    
    # ========================================================================
    # PHASE 1A: Receive and Process Drone Authentication Request
    # ========================================================================
    
    def process_phase1a_auth_request(self, data, client_socket, session):
        """
        Phase 1A: Process incoming drone authentication request.
        
        Receives:
        - OPCODE: 20 (1 byte)
        - TSi: Timestamp (8 bytes)
        - RNi: Nonce (32 bytes)
        - IDDi: Drone ID (variable)
        - Ci: Encrypted KDi,MCC (variable - (c1, c2) pair)
        - Signature: (variable - (r, s) pair)
        """
        try:
            if data[0] != 20:
                print(f"[MCC] Invalid opcode in Phase 1A: {data[0]}")
                return False
            
            offset = 1
            
            # Parse timestamp
            tsi = struct.unpack('>Q', data[offset:offset+8])[0]
            offset += 8
            session.timestamp_drone = tsi
            
            # Parse nonce (32 bytes)
            rni = data[offset:offset+32]
            offset += 32
            session.nonce_drone = rni
            
            # Parse drone ID
            iddi_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            iddi = data[offset:offset+iddi_len]
            offset += iddi_len
            session.drone_id = iddi.decode('utf-8') if isinstance(iddi, bytes) else iddi
            
            # Parse encrypted Ci (c1, c2 pair)
            c1, offset = bytes_from_int_variable(data, offset)
            c2, offset = bytes_from_int_variable(data, offset)
            ci = (c1, c2)
            
            # Parse signature (r, s pair)
            sig_r, offset = bytes_from_int_variable(data, offset)
            sig_s, offset = bytes_from_int_variable(data, offset)
            signature = (sig_r, sig_s)
            
            # Reconstruct message M1A for signature verification
            # M1A = TSi || RNi || IDDi || Ci
            msg_1a = struct.pack('>Q', tsi)
            msg_1a += rni
            msg_1a += struct.pack('>I', iddi_len) + iddi
            msg_1a += int_to_bytes_variable(c1) + int_to_bytes_variable(c2)
            
            # Note: For full implementation, drone's public key would come from PKI
            # For demo, we'll accept and proceed
            print(f"[MCC] Phase 1A: Received auth from drone {session.drone_id}")
            
            # Verify timestamp freshness (within 30 seconds)
            current_time = int(time.time() * 1000)
            time_diff = (current_time - tsi) / 1000.0
            if time_diff > 30 or time_diff < -5:
                print(f"[MCC] Phase 1A: Timestamp too old/future: {time_diff}s")
                return False
            
            # Decrypt Ci to get KDi,MCC
            # Note: In real system, would use drone's certificate
            # For this demo, create public key for verification
            try:
                shared_secret = elgamal_decrypt(ci, self.keypair)
                session.shared_secret = shared_secret
                print(f"[MCC] Phase 1A: Decrypted shared secret")
                return True
            except Exception as e:
                print(f"[MCC] Phase 1A: Failed to decrypt: {e}")
                return False
            
        except Exception as e:
            print(f"[MCC] Phase 1A Error: {e}")
            return False
    
    # ========================================================================
    # PHASE 1B: Send MCC Authentication Response
    # ========================================================================
    
    def send_phase1b_response(self, session):
        """
        Phase 1B: Send MCC authentication response.
        
        Sends:
        - OPCODE: 30 (1 byte)
        - TSMCC: MCC Timestamp (8 bytes)
        - RNMCC: MCC Nonce (32 bytes)
        - IDMCC: MCC ID (variable)
        - CMCC: Encrypted KDi,MCC (variable)
        - Signature: (variable)
        """
        try:
            # Generate MCC timestamp and nonce
            tsmcc = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
            rnmcc = struct.pack('>Q', tsmcc ^ 0xDEADBEEF)  # Simple nonce
            rnmcc += struct.pack('>Q', int(time.time() * 1000000) ^ 0xCAFEBABE)
            rnmcc = (rnmcc + b'\x00' * 32)[:32]  # Pad to 32 bytes
            
            session.timestamp_mcc = tsmcc
            session.nonce_mcc = rnmcc
            
            idmcc = b"MCC_PRIMARY"
            
            # Create public key for drone (for demo, we create a dummy one)
            # In real system, this comes from PKI
            drone_public_key = ElGamalKey(self.p, self.g, y=42)  # Dummy
            session.drone_public_key = drone_public_key
            
            # Encrypt shared secret with drone's "public key"
            # For demo: just use the shared secret directly
            shared_secret = session.shared_secret
            
            # For this implementation, send encrypted with a test key
            # In real system, would use drone's actual public key
            encrypted_secret = elgamal_encrypt(shared_secret, drone_public_key)
            
            # Create message M1B = TSMCC || RNMCC || IDMCC || CMCC
            msg_1b = struct.pack('>Q', tsmcc)
            msg_1b += rnmcc
            msg_1b += struct.pack('>I', len(idmcc)) + idmcc
            msg_1b += int_to_bytes_variable(encrypted_secret[0])
            msg_1b += int_to_bytes_variable(encrypted_secret[1])
            
            # Sign message
            msg_hash = hash_sha256_int(msg_1b) % (self.p - 1)
            signature = elgamal_sign(msg_hash, self.keypair)
            
            # Pack full message
            full_msg = struct.pack('B', 30)  # OPCODE 30
            full_msg += msg_1b
            full_msg += int_to_bytes_variable(signature[0])
            full_msg += int_to_bytes_variable(signature[1])
            
            # Send
            session.socket.sendall(full_msg)
            print(f"[MCC] Phase 1B: Sent response to {session.drone_id}")
            
        except Exception as e:
            print(f"[MCC] Phase 1B Error: {e}")
    
    # ========================================================================
    # PHASE 2: Session Key Derivation & Confirmation
    # ========================================================================
    
    def process_phase2_confirmation(self, session, data):
        """
        Phase 2: Verify drone's session key confirmation.
        
        Receives:
        - OPCODE: 40 (1 byte)
        - HMAC: HMAC-SHA256(SKDi,MCC, IDDi || TSfinal) (32 bytes)
        """
        try:
            if data[0] != 40:
                print(f"[MCC] Invalid opcode in Phase 2: {data[0]}")
                return False
            
            # Derive session key using same formula
            # SKDi,MCC = SHA256(KDi,MCC || TSi || TSMCC || RNi || RNMCC)
            sk_material = int_to_bytes(session.shared_secret, 32)
            sk_material += struct.pack('>Q', session.timestamp_drone)
            sk_material += struct.pack('>Q', session.timestamp_mcc)
            sk_material += session.nonce_drone
            sk_material += session.nonce_mcc
            
            session.session_key = hash_sha256(sk_material)
            
            # Compute expected HMAC
            final_ts = struct.pack('>Q', int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)
            hmac_data = session.drone_id.encode('utf-8') if isinstance(session.drone_id, str) else session.drone_id
            hmac_data += final_ts
            
            expected_hmac = hmac_sha256(session.session_key, hmac_data)
            
            # Compare with received HMAC
            received_hmac = data[1:33]
            
            if expected_hmac == received_hmac:
                # Success - mark as authenticated
                session.authenticated = True
                session.timestamp_auth = time.time()
                
                with self.drones_lock:
                    self.drones[session.drone_id] = session
                
                # Send success
                response = struct.pack('B', 50)  # OPCODE 50: SUCCESS
                session.socket.sendall(response)
                print(f"[MCC] Phase 2: Authentication successful for {session.drone_id}")
                return True
            else:
                print(f"[MCC] Phase 2: HMAC mismatch for {session.drone_id}")
                response = struct.pack('B', 60)  # OPCODE 60: MISMATCH
                session.socket.sendall(response)
                return False
            
        except Exception as e:
            print(f"[MCC] Phase 2 Error: {e}")
            return False
    
    # ========================================================================
    # Connection Handler
    # ========================================================================
    
    def handle_drone_connection(self, client_socket, address):
        """
        Thread function to handle a single drone connection.
        
        Flow:
        1. Send Phase 0 parameters
        2. Receive and process Phase 1A
        3. Send Phase 1B response
        4. Receive and process Phase 2 confirmation
        5. Keep connection alive for commands
        """
        session = DroneSession("UNKNOWN", client_socket, address)
        
        try:
            print(f"[MCC] New connection from {address}")
            
            # Phase 0: Send parameters
            self.send_phase0_params(client_socket)
            time.sleep(0.1)
            
            # Phase 1A: Receive auth request
            data = client_socket.recv(4096)
            if not data or not self.process_phase1a_auth_request(data, client_socket, session):
                print(f"[MCC] Phase 1A failed")
                return
            
            time.sleep(0.1)
            
            # Phase 1B: Send response
            self.send_phase1b_response(session)
            time.sleep(0.1)
            
            # Phase 2: Receive confirmation
            data = client_socket.recv(4096)
            if not data or not self.process_phase2_confirmation(session, data):
                print(f"[MCC] Phase 2 failed")
                return
            
            print(f"[MCC] {session.drone_id} fully authenticated")
            
            # Phase 3: Keep connection alive for commands/broadcasts
            while self.running and session.authenticated:
                try:
                    # Wait for incoming messages with timeout
                    client_socket.settimeout(5.0)
                    data = client_socket.recv(1)
                    if not data:
                        break
                    # Handle incoming messages if needed
                except socket.timeout:
                    continue
                except:
                    break
            
        except Exception as e:
            print(f"[MCC] Error handling drone {session.drone_id}: {e}")
        
        finally:
            # Cleanup
            with self.drones_lock:
                if session.drone_id in self.drones:
                    del self.drones[session.drone_id]
            
            try:
                client_socket.close()
            except:
                pass
            
            print(f"[MCC] Closed connection from {address}")
    
    # ========================================================================
    # Server Main Loop
    # ========================================================================
    
    def start_server(self):
        """Main server loop - accepts connections and spawns threads."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[MCC] Server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    
                    # Handle in separate thread
                    thread = threading.Thread(
                        target=self.handle_drone_connection,
                        args=(client_socket, address),
                        daemon=True
                    )
                    thread.start()
                    self.threads.append(thread)
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    if self.running:
                        print(f"[MCC] Accept error: {e}")
        
        except Exception as e:
            print(f"[MCC] Server error: {e}")
        
        finally:
            self.running = False
            if self.server_socket:
                self.server_socket.close()
    
    # ========================================================================
    # Phase 3: Group Key Broadcast
    # ========================================================================
    
    def cmd_broadcast(self, command):
        """
        Phase 3: Broadcast command to all authenticated drones.
        
        Steps:
        1. Aggregate all session keys
        2. Derive group key GK
        3. Send GK to each drone (encrypted with their SK)
        4. Send command encrypted with GK
        """
        with self.drones_lock:
            if not self.drones:
                print("[MCC] No authenticated drones to broadcast to")
                return
            
            auth_drones = [s for s in self.drones.values() if s.authenticated]
            if not auth_drones:
                print("[MCC] No authenticated drones")
                return
            
            # Step 1: Collect all session keys
            session_keys = [s.session_key for s in auth_drones]
            
            # Step 2: Derive group key
            gk_material = b''.join(session_keys)
            gk_material += int_to_bytes(self.keypair.x, 256)
            group_key = hash_sha256(gk_material)
            
            print(f"[MCC] Generated Group Key: {group_key.hex()[:32]}...")
            
            # Step 3: Distribute GK to each drone
            for session in auth_drones:
                try:
                    iv, encrypted_gk = aes_encrypt(session.session_key, group_key)
                    
                    # Send OPCODE 70 (GROUP_KEY)
                    msg = struct.pack('B', 70) + iv + encrypted_gk
                    session.socket.sendall(msg)
                    
                    print(f"[MCC] Sent GK to {session.drone_id}")
                except Exception as e:
                    print(f"[MCC] Failed to send GK to {session.drone_id}: {e}")
            
            # Step 4: Broadcast encrypted command
            time.sleep(0.5)
            
            if isinstance(command, str):
                command = command.encode('utf-8')
            
            iv, encrypted_cmd = aes_encrypt(group_key, command)
            hmac_tag = hmac_sha256(group_key, encrypted_cmd)
            
            msg = struct.pack('B', 80) + iv + encrypted_cmd + hmac_tag
            
            for session in auth_drones:
                try:
                    session.socket.sendall(msg)
                    print(f"[MCC] Broadcast to {session.drone_id}")
                except Exception as e:
                    print(f"[MCC] Failed to broadcast to {session.drone_id}: {e}")
    
    # ========================================================================
    # CLI Commands
    # ========================================================================
    
    def cmd_list_drones(self):
        """Display all connected drones."""
        with self.drones_lock:
            if not self.drones:
                print("No drones connected")
                return
            
            print("\n" + "="*70)
            print("Active Drones:")
            print("-" * 70)
            print(f"{'Drone ID':<20} | {'Address':<25} | {'Status':<15}")
            print("-" * 70)
            
            for drone_id, session in self.drones.items():
                status = "Authenticated" if session.authenticated else "Connecting"
                print(f"{drone_id:<20} | {str(session.address):<25} | {status:<15}")
            
            print("-" * 70)
            print(f"Total: {len(self.drones)} drone(s)")
            print("="*70 + "\n")
    
    def cmd_broadcast(self, command):
        """Send command to all drones."""
        print(f"\n[MCC] Broadcasting command: {command}")
        self.cmd_broadcast(command)
    
    def cmd_shutdown(self):
        """Shutdown server."""
        print("\n[MCC] Initiating shutdown...")
        
        # Send shutdown signal to all drones
        with self.drones_lock:
            for session in self.drones.values():
                try:
                    msg = struct.pack('B', 90)  # OPCODE 90: SHUTDOWN
                    session.socket.sendall(msg)
                except:
                    pass
        
        self.running = False
        time.sleep(1)
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
    
    # ========================================================================
    # CLI Interface
    # ========================================================================
    
    def cli_interface(self):
        """Interactive CLI for MCC operator."""
        print("\n[MCC] Command Interface Ready")
        print("Commands: list | broadcast <cmd> | shutdown | status")
        print("="*70)
        
        while self.running:
            try:
                user_input = input("MCC> ").strip()
                
                if not user_input:
                    continue
                
                if user_input == "list":
                    self.cmd_list_drones()
                
                elif user_input == "status":
                    with self.drones_lock:
                        print(f"\nServer running: {self.running}")
                        print(f"Connected drones: {len(self.drones)}")
                        auth_count = sum(1 for s in self.drones.values() if s.authenticated)
                        print(f"Authenticated: {auth_count}")
                
                elif user_input.startswith("broadcast "):
                    cmd = user_input[10:]
                    self.cmd_broadcast(cmd)
                
                elif user_input == "shutdown":
                    self.cmd_shutdown()
                    break
                
                else:
                    print("Unknown command. Use: list | broadcast <cmd> | shutdown | status")
                
            except KeyboardInterrupt:
                print("\n[MCC] Shutting down...")
                self.cmd_shutdown()
                break
            except Exception as e:
                print(f"[MCC] CLI Error: {e}")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="UAV Mission Control Center")
    parser.add_argument('--host', default='localhost', help='Bind address')
    parser.add_argument('--port', type=int, default=5555, help='Listen port')
    parser.add_argument('--security-level', type=int, default=2048, 
                       help='Cryptographic security level (bits)')
    
    args = parser.parse_args()
    
    # Create MCC
    mcc = MissionControlCenter(
        host=args.host,
        port=args.port,
        security_level=args.security_level
    )
    
    # Start server in background thread
    server_thread = threading.Thread(target=mcc.start_server, daemon=True)
    server_thread.start()
    
    # Run CLI in main thread
    try:
        mcc.cli_interface()
    except KeyboardInterrupt:
        print("\n[MCC] Interrupted")
    finally:
        mcc.running = False
        time.sleep(1)


if __name__ == "__main__":
    main()
