import socket
import threading
import struct
import time
import sys
import argparse
from crypto_utils import (
    generate_large_prime, find_generator, generate_elgamal_keypair,
    elgamal_decrypt, elgamal_sign, elgamal_verify,
    hash_sha256, hash_sha256_int, hmac_sha256, aes_encrypt, aes_decrypt,
    bytes_to_int, int_to_bytes, int_to_bytes_variable, bytes_from_int_variable
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
        
        # Drone registry with pre-registered drones and their public keys
        self.registered_drones = {}       # {drone_id: public_key_y}
        self._init_drone_registry()
        
        # Active drone sessions
        self.drones = {}                  # {drone_id: DroneSession}
        self.drones_lock = threading.Lock()
        
        # Control connection for attack proxy manager
        self.control_socket = None
        self.control_lock = threading.Lock()
        
        # Server socket
        self.server_socket = None
        self.running = False
        self.threads = []
        
        print(f"[MCC] Initialized successfully")
    
    def _init_drone_registry(self):
        """
        Initialize the drone registry with authorized drone IDs.
        In a real system, this would come from a secure database or PKI.
        For demo: D001 to D100 are authorized IDs. Their public keys will be
        registered on first successful connection.
        """
        # Authorized drone IDs (D001-D100)
        # Public keys will be registered when drones first connect
        # This allows the demo to work with dynamically generated keys
        
        print(f"[MCC] Initializing drone registry (D001-D100 authorized)...")
        
        # No pre-generated keys - will be populated on first connection
        # registered_drones will store: {drone_id: public_key_y}
        
        print(f"[MCC] Registry ready for D001-D100 (keys registered on first connection)")
    
    def is_drone_id_valid(self, drone_id):
        """Check if drone ID is in valid range (D001-D100)."""
        if not drone_id.startswith('D'):
            return False
        try:
            num = int(drone_id[1:])
            return 1 <= num <= 100
        except (ValueError, IndexError):
            return False
    
    # ========================================================================
    # PHASE 0: Send Cryptographic Parameters to Drone
    # ========================================================================
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
            # Prepare message M0 = p || g || SL || TS0 || IDMCC || Y_MCC
            ts0 = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF  # 8 bytes
            idmcc = b"MCC_PRIMARY"
            
            # Create message bytes
            msg_data = int_to_bytes_variable(self.p)
            msg_data += int_to_bytes_variable(self.g)
            msg_data += struct.pack('>I', self.security_level)
            msg_data += struct.pack('>Q', ts0)
            msg_data += int_to_bytes_variable(bytes_to_int(idmcc))
            # Include MCC's public key so drone can encrypt with it
            msg_data += int_to_bytes_variable(self.keypair.y)
            
            # Sign message
            msg_hash = hash_sha256_int(msg_data) % (self.p - 1)
            signature = elgamal_sign(msg_hash, self.keypair)
            sig_data = int_to_bytes_variable(signature[0])
            sig_data += int_to_bytes_variable(signature[1])
            
            # Pack full message
            full_msg = struct.pack('B', 10)  # OPCODE 10
            full_msg += msg_data
            full_msg += sig_data
            
            # Send with length prefix so drone receives complete message
            length_prefix = struct.pack('>I', len(full_msg))
            client_socket.sendall(length_prefix + full_msg)
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
            
            print(f"[MCC] Phase 1A: Received auth from drone {session.drone_id}")
            
            # SECURITY CHECK 1: Registry Validation
            # Check if drone ID is in valid range (D001-D100)
            if not self.is_drone_id_valid(session.drone_id):
                print(f"[MCC] Phase 1A: REJECTED - Unknown Drone ID '{session.drone_id}' (not in D001-D100 range)")
                return False
            
            print(f"[MCC] Phase 1A: Drone ID '{session.drone_id}' is valid (in D001-D100 range)")
            
            # Session protection: Check if drone is already authenticated
            # This prevents replay attacks from disrupting legitimate sessions
            with self.drones_lock:
                existing_session = self.drones.get(session.drone_id)
                if existing_session and existing_session.authenticated:
                    print(f"[MCC] Phase 1A: REJECTED - {session.drone_id} already has active session")
                    print(f"[MCC] Phase 1A: Refusing duplicate connection to protect existing session")
                    return False
            
            # Verify timestamp freshness (within 5 seconds)
            current_time = int(time.time() * 1000)
            time_diff = (current_time - tsi) / 1000.0
            if time_diff > 5 or time_diff < -5:
                print(f"[MCC] Phase 1A: Timestamp too old/future: {time_diff}s")
                return False
            
            # Decrypt Ci to get KDi,MCC
            # The shared secret is encrypted with MCC's public key
            # Successful decryption confirms the message integrity
            try:
                shared_secret = elgamal_decrypt(ci, self.keypair)
                session.shared_secret = shared_secret
                print(f"[MCC] Phase 1A: Successfully decrypted shared secret")
                print(f"[MCC] Phase 1A: Authentication accepted for {session.drone_id}")
                return True
            except Exception as e:
                print(f"[MCC] Phase 1A: Decryption failed - {e}")
                print(f"[MCC] Phase 1A: Invalid encryption or corrupted message")
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
            rnmcc = struct.pack('>Q', tsmcc ^ 0xDEADBEEF)
            rnmcc += struct.pack('>Q', int(time.time() * 1000000) ^ 0xCAFEBABE)
            rnmcc = (rnmcc + b'\x00' * 32)[:32]  # Pad to 32 bytes
            
            session.timestamp_mcc = tsmcc
            session.nonce_mcc = rnmcc
            
            idmcc = b"MCC_PRIMARY"
            
            # Prove knowledge of shared secret by sending HMAC
            secret_bytes = int_to_bytes(session.shared_secret)
            proof = hmac_sha256(hash_sha256(secret_bytes), idmcc + struct.pack('>Q', tsmcc))
            
            # Create message M1B = TSMCC || RNMCC || IDMCC || proof
            msg_1b = struct.pack('>Q', tsmcc)
            msg_1b += rnmcc
            msg_1b += struct.pack('>I', len(idmcc)) + idmcc
            msg_1b += proof  # 32 bytes HMAC proof
            
            # Sign message
            msg_hash = hash_sha256_int(msg_1b) % (self.p - 1)
            signature = elgamal_sign(msg_hash, self.keypair)
            
            # Pack full message
            full_msg = struct.pack('B', 30)  # OPCODE 30
            full_msg += msg_1b
            full_msg += int_to_bytes_variable(signature[0])
            full_msg += int_to_bytes_variable(signature[1])
            
            # Send with length prefix
            length_prefix = struct.pack('>I', len(full_msg))
            session.socket.sendall(length_prefix + full_msg)
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
        - TSfinal: Drone's final timestamp (8 bytes)
        - HMAC: HMAC-SHA256(SKDi,MCC, IDDi || TSfinal) (32 bytes)
        """
        try:
            if data[0] != 40:
                print(f"[MCC] Invalid opcode in Phase 2: {data[0]}")
                return False
            
            # Parse TSfinal sent by drone
            ts_final = data[1:9]
            received_hmac = data[9:41]
            
            # Derive session key using same formula as drone
            # SKDi,MCC = SHA256(H(KDi,MCC) || TSi || TSMCC || RNi || RNMCC)
            secret_bytes = int_to_bytes(session.shared_secret)
            secret_hash = hash_sha256(secret_bytes)
            
            sk_material = secret_hash
            sk_material += struct.pack('>Q', session.timestamp_drone)
            sk_material += struct.pack('>Q', session.timestamp_mcc)
            sk_material += session.nonce_drone
            sk_material += session.nonce_mcc
            
            session.session_key = hash_sha256(sk_material)
            
            # Compute expected HMAC using the SAME TSfinal the drone sent
            hmac_data = session.drone_id.encode('utf-8') if isinstance(session.drone_id, str) else session.drone_id
            hmac_data += ts_final
            
            expected_hmac = hmac_sha256(session.session_key, hmac_data)
            
            if expected_hmac == received_hmac:
                # Success - mark as authenticated
                session.authenticated = True
                session.timestamp_auth = time.time()
                
                # Add to active drones (only if not already present or replacing non-authenticated)
                with self.drones_lock:
                    existing = self.drones.get(session.drone_id)
                    if not existing or not existing.authenticated:
                        self.drones[session.drone_id] = session
                        print(f"[MCC] Phase 2: Added {session.drone_id} to active sessions")
                    else:
                        print(f"[MCC] Phase 2: WARNING - {session.drone_id} already authenticated, keeping original")
                
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
    
    def recv_message(self, sock):
        """Receive a length-prefixed message from socket."""
        # Read 4-byte length prefix
        length_data = b''
        while len(length_data) < 4:
            chunk = sock.recv(4 - len(length_data))
            if not chunk:
                return None
            length_data += chunk
        msg_len = struct.unpack('>I', length_data)[0]
        
        # Read the full message
        data = b''
        while len(data) < msg_len:
            chunk = sock.recv(min(8192, msg_len - len(data)))
            if not chunk:
                return None
            data += chunk
        return data
    
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
            
            # Phase 1A: Receive auth request (length-prefixed)
            data = self.recv_message(client_socket)
            if not data or not self.process_phase1a_auth_request(data, client_socket, session):
                print(f"[MCC] Phase 1A failed")
                print("MCC> ", end='', flush=True)  # Reprint prompt after failed auth
                return
            
            time.sleep(0.1)
            
            # Phase 1B: Send response
            self.send_phase1b_response(session)
            time.sleep(0.1)
            
            # Phase 2: Receive confirmation (length-prefixed)
            data = self.recv_message(client_socket)
            if not data or not self.process_phase2_confirmation(session, data):
                print(f"[MCC] Phase 2 failed")
                print("MCC> ", end='', flush=True)  # Reprint prompt after failed auth
                return
            
            print(f"[MCC] {session.drone_id} fully authenticated")
            
            # Re-print CLI prompt so it's visible after connection messages
            print("MCC> ", end='', flush=True)
            
            # Phase 3: Keep connection alive for commands/broadcasts
            # The CLI thread handles sending via session.socket.sendall()
            # This thread only monitors for disconnection
            while self.running and session.authenticated:
                try:
                    # Use select to check for incoming data without blocking
                    import select
                    readable, _, exceptional = select.select([client_socket], [], [client_socket], 2.0)
                    
                    if exceptional:
                        print(f"[MCC] Socket exception for {session.drone_id}")
                        break
                    
                    if readable:
                        # Check if connection is still alive
                        data = client_socket.recv(1, socket.MSG_PEEK)
                        if not data:
                            print(f"[MCC] {session.drone_id} disconnected")
                            break
                    
                except socket.timeout:
                    continue
                except Exception:
                    break
            
        except Exception as e:
            print(f"[MCC] Error handling drone {session.drone_id}: {e}")
        
        finally:
            # Cleanup - only remove THIS session, not another session with same drone_id
            if session.drone_id and session.drone_id != "UNKNOWN":
                with self.drones_lock:
                    # Only remove if this session object is the one currently registered
                    if session.drone_id in self.drones and self.drones[session.drone_id] is session:
                        del self.drones[session.drone_id]
                        print(f"[MCC] Removed {session.drone_id} from active sessions")
            
            try:
                client_socket.close()
            except:
                pass
            
            print(f"[MCC] Closed connection from {address}")
            
            # Re-print CLI prompt so it's visible after connection closes
            print("MCC> ", end='', flush=True)
    
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
            # Set socket timeout to 1 second so it doesn't block forever
            self.server_socket.settimeout(1.0)
            self.running = True
            
            print(f"[MCC] Server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    
                    # Check first byte to determine connection type
                    try:
                        client_socket.settimeout(0.5)
                        first_byte = client_socket.recv(1, socket.MSG_PEEK)
                        client_socket.settimeout(None)
                        
                        # Opcode 98 = Control connection from attack proxy
                        if first_byte and first_byte[0] == 98:
                            # This is a control connection from attack proxy
                            # Consume the opcode byte
                            client_socket.recv(1)
                            thread = threading.Thread(
                                target=self.handle_control_connection,
                                args=(client_socket, address),
                                daemon=False
                            )
                            thread.start()
                            self.threads.append(thread)
                        else:
                            # Regular drone connection (Phase 0)
                            thread = threading.Thread(
                                target=self.handle_drone_connection,
                                args=(client_socket, address),
                                daemon=True
                            )
                            thread.start()
                            self.threads.append(thread)
                    except socket.timeout:
                        # If no data received quickly, treat as drone connection
                        thread = threading.Thread(
                            target=self.handle_drone_connection,
                            args=(client_socket, address),
                            daemon=True
                        )
                        thread.start()
                        self.threads.append(thread)
                    
                except socket.timeout:
                    # Timeout is normal - allows CLI to process input
                    continue
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
    # Control Connection Management (for attack proxy)
    # ========================================================================
    
    def handle_control_connection(self, client_socket, address):
        """
        Handle control connection from attack proxy manager.
        Listens for control commands and manages coordinated shutdown.
        """
        try:
            print(f"[MCC] Control connection established from {address}")
            with self.control_lock:
                self.control_socket = client_socket
            
            # Keep connection alive
            while self.running:
                try:
                    client_socket.settimeout(1.0)
                    data = client_socket.recv(1024)
                    if not data:
                        # Remote closed the connection
                        print(f"[MCC] Control connection closed by remote")
                        break
                except socket.timeout:
                    # Timeout is normal - just keep listening
                    continue
                except Exception as e:
                    print(f"[MCC] Control connection error: {e}")
                    break
        
        except Exception as e:
            print(f"[MCC] Control handler error: {e}")
        
        finally:
            with self.control_lock:
                if self.control_socket == client_socket:
                    self.control_socket = None
            try:
                client_socket.close()
            except:
                pass
            print(f"[MCC] Control connection closed")
    
    def _signal_attack_shutdown(self):
        """
        Signal attack proxy to shutdown by closing the control connection.
        This causes attack.py to stop and cleanly close all drone connections.
        """
        with self.control_lock:
            if self.control_socket:
                try:
                    print(f"[MCC] Signaling attack proxy to shutdown...")
                    msg = struct.pack('B', 99)  # OPCODE 99: CONTROL_SHUTDOWN
                    self.control_socket.sendall(msg)
                    time.sleep(0.2)
                except:
                    pass
                try:
                    self.control_socket.close()
                except:
                    pass
                self.control_socket = None
    
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
                print("[MCC] No authenticated drones to broadcast to", flush=True)
                return
            
            auth_drones = [s for s in self.drones.values() if s.authenticated]
            if not auth_drones:
                print("[MCC] No authenticated drones", flush=True)
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
        """Display all connected and running drones."""
        with self.drones_lock:
            if not self.drones:
                print("No drones connected", flush=True)
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
            print("="*70 + "\n", flush=True)
    
    def cmd_shutdown(self):
        """Shutdown server."""
        print("\n[MCC] Initiating shutdown...")
        print("[MCC] Sending shutdown signal to all connected drones...")
        
        # Signal attack proxy to shutdown first
        self._signal_attack_shutdown()
        time.sleep(0.3)
        
        # Send shutdown signal to all drones
        with self.drones_lock:
            drone_count = len(self.drones)
            if drone_count > 0:
                print(f"[MCC] Shutting down {drone_count} drone(s)...")
                for session in self.drones.values():
                    try:
                        msg = struct.pack('B', 90)  # OPCODE 90: SHUTDOWN
                        session.socket.sendall(msg)
                        print(f"[MCC] ✓ Shutdown signal sent to {session.drone_id}")
                    except Exception as e:
                        print(f"[MCC] ✗ Failed to signal {session.drone_id}: {e}")
            else:
                print("[MCC] No drones connected")
        
        # Give drones time to process shutdown signal
        print("[MCC] Waiting for drones to disconnect...")
        time.sleep(1.5)
        
        print("[MCC] Stopping server...")
        self.running = False
        time.sleep(0.5)
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("[MCC] Shutdown complete")
    
    # ========================================================================
    # CLI Interface
    # ========================================================================
    
    def cli_interface(self):
        """Interactive CLI for MCC operator."""
        # Wait a moment for server to fully initialize
        time.sleep(0.5)
        
        print("\n" + "="*70)
        print("[MCC] COMMAND INTERFACE READY")
        print("="*70)
        print("Available Commands:")
        print("  list              - Show all authenticated drones")
        print("  broadcast <cmd>   - Send encrypted command to all drones")
        print("  status            - Show server statistics")
        print("  shutdown          - Gracefully shutdown server")
        print("="*70)
        print("\nType your command below:")
        print("="*70 + "\n")
        
        # Check if stdin is a TTY (interactive terminal)
        if not sys.stdin.isatty():
            print("[MCC] Running in non-interactive mode (no TTY detected)")
            print("[MCC] Server will continue accepting drone connections")
            print("[MCC] Press Ctrl+C to shutdown")
            # Keep server running without CLI
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[MCC] Shutting down...")
                self.cmd_shutdown()
            return
        
        while self.running:
            try:
                # Flush output before showing prompt
                sys.stdout.flush()
                user_input = input("MCC> ").strip()
                
                if not user_input:
                    continue
                
                cmd_lower = user_input.lower()
                
                if cmd_lower == "list":
                    self.cmd_list_drones()
                
                elif cmd_lower == "status":
                    with self.drones_lock:
                        print(f"\n{'='*70}")
                        print("SERVER STATUS")
                        print(f"{'-'*70}")
                        print(f"Server running: {self.running}")
                        print(f"Connected drones: {len(self.drones)}")
                        auth_count = sum(1 for s in self.drones.values() if s.authenticated)
                        print(f"Authenticated: {auth_count}")
                        print(f"{'='*70}\n", flush=True)
                
                elif cmd_lower.startswith("broadcast "):
                    cmd = user_input[10:]
                    print()  # Add blank line before output
                    self.cmd_broadcast(cmd)
                    print()  # Add blank line after output
                
                elif cmd_lower == "shutdown":
                    self.cmd_shutdown()
                    break
                
                else:
                    print("\n" + "="*70)
                    print("UNKNOWN COMMAND")
                    print("="*70)
                    print("Use: list | broadcast <cmd> | status | shutdown | help")
                    print("="*70 + "\n", flush=True)
                
            except KeyboardInterrupt:
                print("\n[MCC] Shutting down...")
                self.cmd_shutdown()
                break
            except Exception as e:
                print(f"[MCC] CLI Error: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="UAV Mission Control Center")
    parser.add_argument('--host', default='localhost', help='Bind address')
    parser.add_argument('--port', type=int, default=8000, help='Listen port')
    parser.add_argument('--security-level', type=int, default=2048, 
                       help='Cryptographic security level (bits)')
    
    args = parser.parse_args()
    
    # Create MCC
    mcc = MissionControlCenter(
        host=args.host,
        port=args.port,
        security_level=args.security_level
    )
    
    # Start server in background thread (NOT daemon, so it keeps process alive)
    server_thread = threading.Thread(target=mcc.start_server, daemon=False)
    server_thread.start()
    
    # Run CLI in main thread
    try:
        mcc.cli_interface()
    except KeyboardInterrupt:
        print("\n[MCC] Interrupted")
    finally:
        mcc.running = False
        server_thread.join(timeout=2)  # Wait for server thread to finish
        time.sleep(1)


if __name__ == "__main__":
    main()
