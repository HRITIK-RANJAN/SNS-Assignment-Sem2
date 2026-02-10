import socket
import threading
import struct
import time
import sys

# Import manual crypto primitives from your utils
from crypto_utils import (
    generate_large_prime, 
    generate_elgamal_keypair,
    elgamal_sign,
    hash_sha256_int,
    int_to_bytes_variable, 
    bytes_from_int_variable,
    int_to_bytes
)

# Configuration
REAL_MCC_HOST = 'localhost'
REAL_MCC_PORT = 8000   # The actual MCC server
PROXY_HOST = 'localhost'
PROXY_PORT = 8001      # The port Drones should connect to

# Safety limits
MAX_PACKET_SIZE = 10 * 1024 * 1024  # 10MB max packet size

# OPCODE Mapping (from PDF specification)
OPCODES = {
    10: "PARAM_INIT",
    20: "AUTH_REQ",
    30: "AUTH_RES",
    40: "SK_CONFIRM",
    50: "SUCCESS",
    60: "ERR_MISMATCH",
    70: "GROUP_KEY",
    80: "GROUP_CMD"
}

class AttackEngine:
    """
    MITM Proxy with dynamic attack capabilities.
    By default: Transparent forwarding (invisible to drone and MCC).
    When armed: Intercepts next matching packet, then resets to NORMAL.
    """
    
    def __init__(self):
        self.attack_mode = "NORMAL"  # NORMAL, REPLAY, TAMPER
        self.running = True
        self.proxy_socket = None
        self.attack_lock = threading.Lock()  # For thread-safe attack state
        self.control_socket = None  # Connection to MCC for shutdown signals
        self.drone_connections = []  # Track all active drone proxy connections
        self.connections_lock = threading.Lock()  # Protect drone connections list

    def log(self, tag, message):
        """Enhanced logging with timestamps."""
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] [{tag}] {message}")

    def get_opcode_name(self, opcode):
        """Get human-readable opcode name."""
        return OPCODES.get(opcode, f"UNKNOWN_{opcode}")
    
    def recv_exact(self, sock, size):
        """
        Receive exactly 'size' bytes from socket.
        Returns bytes if successful, None if connection closed.
        """
        data = b''
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                return None  # Connection closed
            data += chunk
        return data
    
    # ========================================================================
    # BIDIRECTIONAL FORWARDING HANDLERS (A1-Style Architecture)
    # ========================================================================
    
    def handle_drone_to_mcc(self, drone_socket, mcc_socket, addr):
        """
        Forward packets from Drone -> MCC.
        Intercept opportunities: Phase 1A (REPLAY)
        
        Protocol framing:
        - Messages 1-2 (Phase 1A, Phase 2): length-prefixed (4-byte header)
        - After that: raw byte forwarding (drone sends nothing more normally)
        """
        try:
            msg_count = 0
            while self.running:
                if msg_count < 2:
                    # --- LENGTH-PREFIXED PHASE (Phase 1A + Phase 2) ---
                    header = self.recv_exact(drone_socket, 4)
                    if not header:
                        return
                    
                    length = struct.unpack('>I', header)[0]
                    if length == 0 or length > MAX_PACKET_SIZE:
                        self.log("ERROR", f"Invalid packet size: {length}")
                        return
                    
                    payload = self.recv_exact(drone_socket, length)
                    if not payload:
                        return
                    
                    opcode = payload[0]
                    
                    # REPLAY ATTACK: Capture Phase 1A (opcode 20)
                    with self.attack_lock:
                        current_mode = self.attack_mode
                    
                    if opcode == 20 and current_mode == "REPLAY":
                        with self.attack_lock:
                            self.attack_mode = "NORMAL"
                        self.log("ATTACK", "REPLAY triggered")
                        self.handle_replay_attack(header + payload, mcc_socket)
                    else:
                        mcc_socket.sendall(header + payload)
                    
                    msg_count += 1
                else:
                    # --- RAW FORWARDING (post-authentication) ---
                    data = drone_socket.recv(4096)
                    if not data:
                        return
                    mcc_socket.sendall(data)
                
        except Exception as e:
            pass
        finally:
            for sock in [drone_socket, mcc_socket]:
                try:
                    sock.close()
                except:
                    pass
    
    def handle_mcc_to_drone(self, mcc_socket, drone_socket):
        """
        Forward packets from MCC -> Drone.
        Intercept opportunities: Phase 0 (TAMPER)
        
        Protocol framing:
        - Messages 1-2 (Phase 0, Phase 1B): length-prefixed (4-byte header)
        - After that: raw byte forwarding (Phase 2 response + Phase 3 are NOT length-prefixed)
        """
        try:
            msg_count = 0
            while self.running:
                if msg_count < 2:
                    # --- LENGTH-PREFIXED PHASE (Phase 0 + Phase 1B) ---
                    header = self.recv_exact(mcc_socket, 4)
                    if not header:
                        return
                    
                    length = struct.unpack('>I', header)[0]
                    if length == 0 or length > MAX_PACKET_SIZE:
                        self.log("ERROR", f"Invalid packet size: {length}")
                        return
                    
                    payload = self.recv_exact(mcc_socket, length)
                    if not payload:
                        return
                    
                    opcode = payload[0]
                    
                    # TAMPER ATTACK: Modify Phase 0 (opcode 10)
                    with self.attack_lock:
                        current_mode = self.attack_mode
                    
                    if opcode == 10 and current_mode == "TAMPER":
                        with self.attack_lock:
                            self.attack_mode = "NORMAL"
                        self.log("ATTACK", "TAMPER triggered")
                        self.handle_tamper_attack(header, payload, drone_socket)
                    else:
                        drone_socket.sendall(header + payload)
                    
                    msg_count += 1
                else:
                    # --- RAW FORWARDING (Phase 2 response + Phase 3) ---
                    # Phase 2 response (opcode 50/60) is just 1 byte - NO length prefix
                    # Phase 3 messages (opcodes 70, 80, 90) are also NOT length-prefixed
                    data = mcc_socket.recv(4096)
                    if not data:
                        return
                    drone_socket.sendall(data)
                
        except Exception as e:
            pass
        finally:
            for sock in [mcc_socket, drone_socket]:
                try:
                    sock.close()
                except:
                    pass
    
    # ========================================================================
    # ATTACK IMPLEMENTATIONS
    # ========================================================================
    
    def handle_replay_attack(self, packet_data, mcc_socket):
        """
        REPLAY ATTACK on Phase 1A:
        1. Forward packet immediately (so legitimate drone still authenticates)
        2. Wait 7 seconds (exceeds MCC's 5-30s timestamp window)
        3. Replay packet on a NEW connection to MCC
        4. Check if MCC accepts or rejects the stale packet
        """
        self.log("REPLAY", "Forwarding original packet...")
        
        # 1. Forward original packet immediately
        try:
            mcc_socket.sendall(packet_data)
        except Exception as e:
            self.log("ERROR", f"Failed to forward original: {e}")
            return
        
        # 2. Spawn background thread for delayed replay
        def replay_thread():
            self.log("REPLAY", "Waiting 7s...")
            time.sleep(7)
            
            self.log("REPLAY", "Replaying on new connection...")
            try:
                # Open fresh connection to MCC
                replay_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                replay_sock.settimeout(10.0)
                replay_sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
                
                # Receive Phase 0 parameters (required MCC handshake)
                phase0_header = b''
                while len(phase0_header) < 4:
                    chunk = replay_sock.recv(4 - len(phase0_header))
                    if not chunk:
                        raise ConnectionError("Connection closed during Phase 0")
                    phase0_header += chunk
                
                phase0_len = struct.unpack('>I', phase0_header)[0]
                if phase0_len > 0 and phase0_len < MAX_PACKET_SIZE:
                    phase0_data = b''
                    while len(phase0_data) < phase0_len:
                        chunk = replay_sock.recv(phase0_len - len(phase0_data))
                        if not chunk:
                            raise ConnectionError("Connection closed during Phase 0 payload")
                        phase0_data += chunk
                
                # Send the captured (now stale) Phase 1A packet
                replay_sock.sendall(packet_data)
                
                # Wait for MCC response
                replay_sock.settimeout(5.0)
                resp_header = b''
                while len(resp_header) < 4:
                    chunk = replay_sock.recv(4 - len(resp_header))
                    if not chunk:
                        self.log("SUCCESS", "✓ Replay REJECTED (connection closed)")
                        replay_sock.close()
                        return
                    resp_header += chunk
                
                resp_len = struct.unpack('>I', resp_header)[0]
                response = resp_header + replay_sock.recv(resp_len if resp_len < 1024 else 1024)
                
                if not response:
                    self.log("SUCCESS", "✓ Replay REJECTED (connection closed)")
                else:
                    # Parse response opcode
                    if len(response) >= 5:
                        resp_opcode = response[4]  # Skip 4-byte length header
                        if resp_opcode == 60:  # ERR_MISMATCH
                            self.log("SUCCESS", "✓ Replay REJECTED (error response)")
                        elif resp_opcode == 30:  # AUTH_RES
                            self.log("FAILURE", "✗ Replay ACCEPTED (vulnerability!)")
                        else:
                            self.log("REPLAY", f"Opcode: {resp_opcode}")
                
                replay_sock.close()
                
            except socket.timeout:
                self.log("SUCCESS", "✓ Replay REJECTED (timeout)")
            except Exception as e:
                self.log("ERROR", f"Replay failed: {e}")
        
        threading.Thread(target=replay_thread, daemon=True).start()
    
    def handle_tamper_attack(self, header, payload, drone_socket):
        """
        TAMPER ATTACK on Phase 0:
        1. Parse Phase 0 parameters (P, G, SL, TS, ID, Y, Sig)
        2. Replace P with a WEAK prime (e.g., 23 or 512-bit)
        3. Keep signature INVALID (to test signature verification)
        4. Forward corrupted packet to drone
        5. Drone should reject due to signature verification failure
        """
        
        try:
            # Parse original parameters
            offset = 1  # Skip opcode
            orig_p, offset = bytes_from_int_variable(payload, offset)
            
            # Generate weak prime (fast for demo)
            weak_p = 23  # Extremely weak (5-bit prime)
            weak_p_bytes = int_to_bytes_variable(weak_p)
            
            # Reconstruct packet with weak P
            # Structure: Opcode(1) + P(var) + [rest of original packet]
            remaining = payload[offset:]
            
            new_payload = bytearray([10])  # Opcode PHASE_0_PARAMS
            new_payload += weak_p_bytes
            new_payload += remaining
            
            # Recalculate length header
            new_header = struct.pack('>I', len(new_payload))
            
            self.log("TAMPER", f"Replaced P: {orig_p.bit_length()}-bit → {weak_p.bit_length()}-bit")
            
            # Forward tampered packet
            drone_socket.sendall(new_header + bytes(new_payload))
            
        except Exception as e:
            self.log("ERROR", f"Tamper attack failed: {e}")
            # Fallback: forward original
            drone_socket.sendall(header + payload)
    
    # ========================================================================
    # STANDALONE ATTACKS (Separate Connections)
    # ========================================================================
    
    def run_unauthorized_access_suite(self):
        """
        Attack suite testing MCC's defense layers:
        - Registry Validation (Unknown Drone ID)
        """
        print("="*70)
        print("   UNAUTHORIZED ACCESS ATTACK SUITE")
        print("="*70)
        
        # Attack: Unknown Drone ID (outside D001-D100 registry)
        print("\nRegistry Validation Test")
        print("-" * 70)
        print("Testing with unregistered ID: DRONE_666 (not in D001-D100 range)")
        self.attack_unknown_id()
        
        print("\n" + "="*70 + "\n")
    
    def attack_unknown_id(self, fake_id="DRONE_666"):
        """
        Test MCC's registry validation by connecting with unregistered ID.
        MCC registry contains D001-D100, so DRONE_666 is outside valid range.
        Expected: MCC rejects due to unknown drone ID.
        """
        self.log("TEST", f"Unregistered ID: {fake_id} (not in D001-D100 registry)")
        
        try:
            # Generate valid cryptographic parameters
            fake_p = generate_large_prime(512)
            fake_g = 2
            fake_keypair = generate_elgamal_keypair(fake_p, fake_g)
            
            # Connect to MCC
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
            
            # Receive Phase 0 (length-prefixed)
            header = b''
            while len(header) < 4:
                chunk = sock.recv(4 - len(header))
                if not chunk:
                    raise ConnectionError("Connection closed")
                header += chunk
            
            length = struct.unpack('>I', header)[0]
            if length > 0 and length < MAX_PACKET_SIZE:
                phase0 = b''
                while len(phase0) < length:
                    chunk = sock.recv(length - len(phase0))
                    if not chunk:
                        raise ConnectionError("Connection closed")
                    phase0 += chunk
            
            # Craft Phase 1A with UNREGISTERED ID
            ts = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
            nonce = b'\xBB' * 32
            drone_id_bytes = fake_id.encode('utf-8')
            
            # Dummy encrypted secret
            c1_dummy, c2_dummy = 99999, 88888
            
            # Build Phase 1A message
            msg_1a = struct.pack('>Q', ts)
            msg_1a += nonce
            msg_1a += struct.pack('>I', len(drone_id_bytes)) + drone_id_bytes
            msg_1a += int_to_bytes_variable(c1_dummy) + int_to_bytes_variable(c2_dummy)
            
            # Sign with fake key
            msg_hash = hash_sha256_int(msg_1a) % (fake_keypair.p - 1)
            r, s = elgamal_sign(msg_hash, fake_keypair)
            
            # Pack full packet
            full_packet = struct.pack('B', 20)  # Opcode PHASE_1A
            full_packet += msg_1a
            full_packet += int_to_bytes_variable(r) + int_to_bytes_variable(s)
            
            # Send with length prefix
            length_header = struct.pack('>I', len(full_packet))
            sock.sendall(length_header + full_packet)
            
            # Wait for response
            response = sock.recv(1024)
            
            if not response:
                self.log("SUCCESS", "✓ Unknown ID REJECTED")
            elif len(response) > 4:
                opcode = response[4]
                if opcode == 60:  # ERR_MISMATCH
                    self.log("SUCCESS", "✓ Unknown ID REJECTED")
                elif opcode == 30:  # AUTH_RES
                    self.log("FAILURE", "✗ Unknown ID ACCEPTED")
                else:
                    self.log("TEST", f"Opcode: {opcode}")
            
            sock.close()
            
        except Exception as e:
            self.log("ERROR", f"Attack failed: {e}")
    
    # ========================================================================
    # PROXY SERVER
    # ========================================================================
    
    def listen_for_mcc_shutdown(self):
        """
        Listen for shutdown signal from MCC.
        When MCC shuts down, it closes this control connection.
        """
        try:
            # Connect to MCC as control client
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.connect((REAL_MCC_HOST, REAL_MCC_PORT))
            
            # Send control connection opcode
            self.control_socket.sendall(struct.pack('B', 98))
            self.log("CONTROL", f"Control connection established with MCC")
            
            # Wait for shutdown signal or connection close
            while self.running:
                try:
                    self.control_socket.settimeout(1.0)
                    data = self.control_socket.recv(1024)
                    if not data:
                        # MCC closed connection - shutdown signal
                        self.log("CONTROL", "MCC shutdown detected")
                        self.shutdown_all()
                        break
                    
                    # Check for explicit shutdown opcode
                    if data[0] == 99:
                        self.log("CONTROL", "Shutdown signal received from MCC")
                        self.shutdown_all()
                        break
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log("CONTROL", f"Connection lost: {e}")
                    self.shutdown_all()
                    break
        
        except ConnectionRefusedError:
            self.log("CONTROL", "MCC not available for control connection")
        except Exception as e:
            self.log("CONTROL", f"Control connection error: {e}")
    
    def shutdown_all(self):
        """
        Shutdown all proxy connections, which will disconnect all drones.
        """
        self.log("SHUTDOWN", "Closing all drone connections...")
        self.running = False
        
        # Close all drone proxy connections
        with self.connections_lock:
            for drone_sock, mcc_sock in self.drone_connections:
                try:
                    drone_sock.close()
                except:
                    pass
                try:
                    mcc_sock.close()
                except:
                    pass
            self.drone_connections.clear()
        
        # Close proxy server
        if self.proxy_socket:
            try:
                self.proxy_socket.close()
            except:
                pass
        
        self.log("SHUTDOWN", "All connections closed")
    
    def start_proxy(self):
        """
        Main proxy server loop.
        Accepts drone connections and spawns bidirectional forwarding threads.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.proxy_socket = server
        
        try:
            server.bind((PROXY_HOST, PROXY_PORT))
        except OSError as e:
            self.log("ERROR", f"Bind failed on port {PROXY_PORT}: {e}")
            return
        
        server.listen(10)
        server.settimeout(1.0)  # Non-blocking accept
        self.log("PROXY", f"Listening on {PROXY_HOST}:{PROXY_PORT}")
        self.log("PROXY", f"Forwarding to {REAL_MCC_HOST}:{REAL_MCC_PORT}")
        print()
        
        while self.running:
            try:
                # Accept drone connection
                try:
                    drone_sock, addr = server.accept()
                except socket.timeout:
                    continue
                
                # Connect to real MCC
                mcc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    mcc_sock.connect((REAL_MCC_HOST, REAL_MCC_PORT))
                except Exception as e:
                    self.log("ERROR", f"MCC connection failed: {e}")
                    drone_sock.close()
                    continue
                
                # Track this connection
                with self.connections_lock:
                    self.drone_connections.append((drone_sock, mcc_sock))
                
                # Start bidirectional forwarding threads (A1-style)
                t1 = threading.Thread(
                    target=self.handle_drone_to_mcc,
                    args=(drone_sock, mcc_sock, addr),
                    daemon=True
                )
                t2 = threading.Thread(
                    target=self.handle_mcc_to_drone,
                    args=(mcc_sock, drone_sock),
                    daemon=True
                )
                
                t1.start()
                t2.start()
                
            except OSError:
                break
            except Exception as e:
                if self.running:
                    self.log("ERROR", f"Proxy error: {e}")
        
        server.close()
        self.log("PROXY", "Proxy server stopped")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def print_banner():
    """Print attack suite banner."""
    print("\n" + "="*70)
    print("   SECURE UAV ATTACK SUITE - MITM PROXY")
    print("="*70)

def print_menu(engine):
    """Print interactive menu."""
    print(f"\n{'─'*70}")
    print(f"  Mode: {engine.attack_mode}")
    print(f"{'─'*70}")
    print("  [1] REPLAY ATTACK       - Capture & replay Phase 1A")
    print("  [2] TAMPER ATTACK       - Modify Phase 0 parameters")
    print("  [3] UNAUTHORIZED        - Test registry validation")
    print("  [q] QUIT")
    print(f"{'─'*70}")

def input_listener(engine):
    """
    CLI thread for interactive attack control.
    Runs in parallel with proxy server.
    """
    time.sleep(0.5)  # Let proxy start first
    print_banner()
    
    while engine.running:
        print_menu(engine)
        print()
        try:
            choice = input("Select Option > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        
        if choice == '1':
            with engine.attack_lock:
                engine.attack_mode = "REPLAY"
            print("\n✓ REPLAY armed (triggers on next Phase 1A)\n")
            
        elif choice == '2':
            with engine.attack_lock:
                engine.attack_mode = "TAMPER"
            print("\n✓ TAMPER armed (triggers on next Phase 0)\n")
            
        elif choice == '3':
            print()
            engine.run_unauthorized_access_suite()
            
        elif choice == 'q':
            print("\n✓ Shutting down...")
            engine.shutdown_all()
            break
            
        else:
            print("\n✗ Invalid\n")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    engine = AttackEngine()
    
    # Start control connection listener (monitors MCC shutdown)
    control_thread = threading.Thread(target=engine.listen_for_mcc_shutdown, daemon=True)
    control_thread.start()
    
    # Start proxy server in background thread
    proxy_thread = threading.Thread(target=engine.start_proxy, daemon=True)
    proxy_thread.start()
    
    # Run CLI in main thread
    try:
        input_listener(engine)
    except KeyboardInterrupt:
        print("\n\n✓ Interrupted")
    finally:
        engine.shutdown_all()
        sys.exit(0)
