import socket
import time
import random
import hashlib
from protocol_fsm import *

HOST = '127.0.0.1'
PORT = 65433
CLIENT_ID = random.randint(1, 100)  # Random unique ID per client (1-100)
MASTER_KEY = hashlib.sha256(b"basekey" + str(CLIENT_ID).encode()).digest()[:16]  # Derived unique key

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((HOST, PORT))
    except ConnectionRefusedError:
        print(f"[!] Could not connect to {HOST}:{PORT}. Is server.py running?")
        return
    
    try:
        state = ProtocolState(MASTER_KEY, CLIENT_ID)
        print(f"[*] Current Round: {state.round}")
        
        # 1. Send CLIENT_HELLO (Round 0)
        print("[*] Sending HELLO...")
        msg = b"HelloServer"
        # Opcode 10 = HELLO
        packet = state.construct_packet(OP_HELLO, msg, DIR_C2S)
        client.sendall(packet)
        state.ratchet_keys(msg, DIR_C2S) # Update my sending keys

        # 2. Receive SERVER_CHALLENGE (Round 0)
        data = client.recv(4096)
        if not data:
            print("[!] Server disconnected unexpectedly.")
            return

        opcode, plaintext = state.process_incoming_packet(data, DIR_S2C)
        print(f"[*] Server Challenge: {plaintext.decode()}")
        
        if opcode != OP_CHALLENGE:
            raise OpcodeError("Expected Challenge")
        
        state.ratchet_keys(plaintext, DIR_S2C) # Update receiving keys
        state.increment_round() # Round 0 Done

        print("\n[*] Secure Channel Established. Type 'exit' to quit.\n")

        # --- NEW CONTINUOUS LOOP ---
        while True:
            # 1. Get User Input
            user_input = input(f"[Round {state.round}] Enter Message: ")
            
            if user_input.lower() == 'exit':
                print("[*] Closing connection.")
                break
            
            # 2. Send Data
            msg_bytes = user_input.encode()
            packet = state.construct_packet(OP_DATA, msg_bytes, DIR_C2S)
            client.sendall(packet)
            
            # Ratchet Sending Keys
            state.ratchet_keys(msg_bytes, DIR_C2S)

            # 3. Receive Response
            data = client.recv(4096)
            if not data:
                print("[!] Server disconnected.")
                break
                
            opcode, plaintext = state.process_incoming_packet(data, DIR_S2C)
            print(f"[*] Response: {plaintext.decode()}")
            
            # Ratchet Receiving Keys
            state.ratchet_keys(plaintext, DIR_S2C)
            
            # 4. Increment Round
            state.increment_round()
            print("-" * 30)

        print(f"[*] Round {state.round-1} Finished. Next Round: {state.round}")

        # 3. Send CLIENT_DATA (Round 1)
        print("[*] Sending Data (100)...")
        data_msg = b"100"
        packet = state.construct_packet(OP_DATA, data_msg, DIR_C2S)
        client.sendall(packet)
        state.ratchet_keys(data_msg, DIR_C2S)

        # 4. Receive AGGR_RESPONSE (Round 1)
        data = client.recv(4096)
        opcode, plaintext = state.process_incoming_packet(data, DIR_S2C)
        print(f"[*] Aggregation Result: {plaintext.decode()}")
        
        state.ratchet_keys(plaintext, DIR_S2C)
        state.increment_round()
        print("[*] Protocol Complete.")

    except ProtocolError as e:
        print(f"[!] Security Error: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()