import socket
import threading
import struct
import hashlib
from protocol_fsm import *

# Configuration
HOST = '127.0.0.1'
PORT = 65432
# Generate keys for client IDs 1-100
MASTER_KEY_DB = {}
for i in range(1, 101):
    MASTER_KEY_DB[i] = hashlib.sha256(b"basekey" + str(i).encode()).digest()[:16]

# Global aggregate state per round
global_aggregates = {}
aggregate_lock = threading.Lock()

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    state = None
    
    try:
        # 1. Wait for CLIENT_HELLO (Op 10)
        # We read a large chunk to capture the packet. In production, we'd read header first.
        data = conn.recv(4096)
        if not data: return

        # Peek at Client ID (byte index 1) to init state
        client_id = data[1]
        if client_id not in MASTER_KEY_DB:
            print("[-] Unknown Client ID")
            return
        
        # Initialize State
        state = ProtocolState(MASTER_KEY_DB[client_id], client_id)
        print(f"[-] Current Round: {state.round}") 
        
        # Process HELLO
        opcode, msg = state.process_incoming_packet(data, expected_direction=DIR_C2S)
        if opcode != OP_HELLO:
            raise OpcodeError("Expected HELLO")
        
        print(f"[{client_id}] Received HELLO: {msg.decode()}")
        
        # Ratchet C2S keys (using ciphertext or msg hash - simplified here using msg)
        state.ratchet_keys(msg, DIR_C2S)
        
        # 2. Send SERVER_CHALLENGE (Op 20)
        challenge_msg = b"SolveThis"
        resp_packet = state.construct_packet(OP_CHALLENGE, challenge_msg, DIR_S2C)
        conn.sendall(resp_packet)
        state.ratchet_keys(challenge_msg, DIR_S2C) # Ratchet S2C
        
        # Update Round (Round 0 Complete)
        state.increment_round()
        print(f"[{client_id}] Round 0 Complete. Entering Round 1.")

        while True:
            try:
                # 1. Wait for Data
                data = conn.recv(4096)
                if not data:
                    print(f"[{client_id}] Client disconnected.")
                    break

                # 2. Process Packet
                opcode, msg = state.process_incoming_packet(data, expected_direction=DIR_C2S)
                
                # Check if client wants to quit (Optional Opcode 60 check could go here)
                if opcode != OP_DATA:
                    raise OpcodeError(f"Expected DATA, got {opcode}")
                
                received_text = msg.decode()
                print(f"[{client_id}] Round {state.round} | Received: {received_text}")
                
                # Aggregate numeric data (assume comma-separated integers)
                try:
                    numbers = [int(x.strip()) for x in received_text.split(',')]
                    local_aggregated = sum(numbers)
                    print(f"[{client_id}] Local Aggregated (sum): {local_aggregated}")
                except ValueError:
                    # If not numeric, use byte length of the message
                    local_aggregated = len(msg)
                    print(f"[{client_id}] Non-numeric data, using byte length: {local_aggregated}")
                
                # Update global aggregate for this round
                with aggregate_lock:
                    global global_aggregates
                    current_round = state.round
                    if current_round not in global_aggregates:
                        global_aggregates[current_round] = 1
                    global_aggregates[current_round] *= local_aggregated
                    print(f"[{client_id}] Round {current_round} Global Aggregate Updated to: {global_aggregates[current_round]}")
                
                # Ratchet Receiving Keys
                state.ratchet_keys(msg, DIR_C2S)

                # 3. Send Global Aggregated Response for this round using evolved keys
                aggr_resp = str(global_aggregates[current_round]).encode()
                resp_packet = state.construct_packet(OP_AGGR_RESP, aggr_resp, DIR_S2C)
                conn.sendall(resp_packet)
                
                # Ratchet Sending Keys
                state.ratchet_keys(aggr_resp, DIR_S2C)
                
                # 4. Increment Round
                state.increment_round()
                print(f"[{client_id}] Round {state.round-1} Finished. Waiting for Round {state.round}...")

            except ProtocolError as e:
                print(f"[!] SECURITY ALERT: {e}")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                break

    except ProtocolError as e:
        print(f"[!] SECURITY ALERT: {e}")
        # Send TERMINATE Opcode if possible
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")
    
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()