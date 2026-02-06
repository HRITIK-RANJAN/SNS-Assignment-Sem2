import socket
import threading
import time
import sys

REAL_SERVER_IP = '127.0.0.1'
REAL_SERVER_PORT = 65432
PROXY_IP = '127.0.0.1'
PROXY_PORT = 65433

# Global State
pending_attack = None

def handle_c2s(client_socket, server_socket, client_addr):
    """
    Client -> Server (Handles Replay, Tamper, Drop)
    """
    global pending_attack
    
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            # --- ATTACK LOGIC (C2S) ---
            if pending_attack in ['r', 't', 'd']:
                mode = pending_attack
                pending_attack = None # Disarm immediately
                
                print(f"\n\n[!!!] ATTACK TRIGGERED on Client {client_addr} ({mode.upper()})...")

                # 1. REPLAY ATTACK
                if mode == 'r':
                    print("      >>> Sending packet twice (Replay)...")
                    server_socket.sendall(data)
                    time.sleep(0.1)
                    server_socket.sendall(data)
                    print("      [+] Replay Sent. Closing connection...")
                    time.sleep(1) # Give server time to log the error
                    break # FORCE DISCONNECT CLIENT

                # 2. TAMPER ATTACK
                elif mode == 't':
                    print("      >>> Corrupting ciphertext (Tamper)...")
                    bad_data = bytearray(data)
                    if len(bad_data) > 32:
                        bad_data[-20] = bad_data[-20] ^ 0xFF
                    server_socket.sendall(bytes(bad_data))
                    print("      [+] Bad Packet Sent. Closing connection...")
                    time.sleep(1) # Give server time to log the error
                    break # FORCE DISCONNECT CLIENT

                # 3. DROP ATTACK (Desync)
                elif mode == 'd':
                    print("      >>> Dropping packet (Desync)...")
                    print("      [+] Packet eaten. Connection stays open but stale.\n[MITM] > ", end='', flush=True)
                    time.sleep(1)
                    break

            # --- NORMAL FORWARDING ---
            server_socket.sendall(data)
            
    except Exception:
        pass
    finally:
        # This will close the socket and unblock the Client's recv()
        client_socket.close()
        server_socket.close()

def handle_s2c(server_socket, client_socket):
    global pending_attack
    try:
        while True:
            data = server_socket.recv(4096)
            if not data:
                break
            
            # --- ATTACK LOGIC (S2C) ---
            if pending_attack == 'f':
                pending_attack = None
                print("\n\n[!!!] ATTACK TRIGGERED (REFLECTION)...")
                
                # 1. Reflect packet back to server
                server_socket.sendall(data)
                print("      [+] Reflection Sent.")
                
                # 2. FORCE KILL THE CLIENT (The Fix)
                print("      [+] Shutting down Client connection to prevent hang...")
                try:
                    # SHUT_RDWR forces the client's recv() to return empty bytes IMMEDIATELY
                    client_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass 
                
                client_socket.close()
                break # Stop the thread

            # --- NORMAL FORWARDING ---
            client_socket.sendall(data)
    except:
        pass
    finally:
        client_socket.close()
        server_socket.close()

def input_listener():
    """
    Continuous User Interface Loop
    """
    global pending_attack
    
    time.sleep(1)
    print("\n" + "="*50)
    print(" MITM CONTROL PANEL")
    print(" [r] Replay Attack")
    print(" [t] Tamper Attack")
    print(" [d] Drop (Desync) Attack")
    print(" [f] Reflection Attack")
    print(" [c] Cancel")
    print("="*50)
    
    while True:
        print("\n[MITM] Enter Command > ", end='', flush=True)
        try:
            user_input = input().strip().lower()
        except EOFError:
            break

        if user_input in ['r', 't', 'd', 'f']:
            pending_attack = user_input
            print(f"[***] ARMED: Next packet will trigger '{user_input.upper()}' attack.")
        elif user_input == 'c':
            pending_attack = None
            print("[***] DISARMED.")
        else:
            print("[*] Invalid.")

def start_proxy():
    threading.Thread(target=input_listener, daemon=True).start()

    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        proxy_server.bind((PROXY_IP, PROXY_PORT))
    except OSError:
        print(f"[!] Port {PROXY_PORT} is busy.")
        return

    proxy_server.listen(10)

    while True:
        try:
            client_socket, addr = proxy_server.accept()
            real_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                real_server.connect((REAL_SERVER_IP, REAL_SERVER_PORT))
            except:
                client_socket.close()
                continue

            t1 = threading.Thread(target=handle_c2s, args=(client_socket, real_server, addr))
            t2 = threading.Thread(target=handle_s2c, args=(real_server, client_socket))
            t1.start()
            t2.start()
            
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    start_proxy()