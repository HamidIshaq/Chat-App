import socket
import json
import os
import threading
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib

# Global variables to track active connections
active_connections = {}
active_connections_lock = threading.Lock()
server_socket = None
shutdown_flag = False

# Diffie-Hellman public parameters (2048-bit MODP group from RFC 3526)
P = 23
G = 2

# In-memory user store (replace with database in production)
users = {}

# Callback functions for broadcasting
status_update_callback = None
message_broadcast_callback = None

def register_status_update_callback(callback):
    global status_update_callback
    status_update_callback = callback

def register_message_broadcast_callback(callback):
    global message_broadcast_callback
    message_broadcast_callback = callback

# Diffie-Hellman Key Exchange
def diffie_hellman_exchange():
    private_key = os.urandom(16)
    public_key = pow(G, int.from_bytes(private_key, 'big'), P)
    print(f"Server generated private key: {private_key.hex()}, public key: {public_key}")
    return private_key, public_key

# AES decryption
def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    print(f"Server decrypted data: {decrypted_data.decode()}")
    return decrypted_data.decode()

def derive_message_key(shared_secret, username):
    key_material = f"{username}{shared_secret}".encode()
    key = hashlib.sha256(key_material).digest()[:16]  # AES-128 bit key
    print(f"Server derived message key: {key.hex()} for username: {username}")
    return key

def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    print(f"Server encrypting data: {data}, key: {key.hex()}, iv: {iv.hex()}")
    return iv + encrypted_data

def chat(conn, message_key, username, client_address):
    try:
        print(f"Chat session started with {username}. Type 'bye' to end the chat.")
        
        with active_connections_lock:
            active_connections[username] = {
                'connection': conn,
                'message_key': message_key,
                'address': client_address
            }
        
        broadcast_status_update(username, client_address, True)
        
        while True:
            try:
                encrypted_message = conn.recv(1024)
                if not encrypted_message:
                    break
                    
                message = decrypt_data(message_key, encrypted_message)
                print(f"Client ({username}): {message}")
                
                broadcast_message(username, message)

                if message.lower() == "bye":
                    print(f"Chat with {username} ended.")
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break
    finally:
        with active_connections_lock:
            if username in active_connections:
                del active_connections[username]
        
        broadcast_status_update(username, client_address, False)
        conn.close()

def send_server_message(username, message):
    with active_connections_lock:
        if username in active_connections:
            client_info = active_connections[username]
            encrypted_response = encrypt_data(client_info['message_key'], message)
            client_info['connection'].sendall(encrypted_response)
            return True
    return False

def broadcast_status_update(username, client_address, connected=True):
    if status_update_callback:
        status_update_callback(username, client_address, connected)

def broadcast_message(username, message):
    if message_broadcast_callback:
        message_broadcast_callback(username, message)

def receive_full_data(conn, buffer_size=1024, timeout=5):
    """Receive data until a newline is encountered or timeout occurs."""
    conn.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = conn.recv(buffer_size)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
    except socket.timeout:
        print("Timeout while receiving data")
    finally:
        conn.settimeout(None)
    return data

def start_server():
    global server_socket, shutdown_flag
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("Server started on localhost:12345")
    
    try:
        while not shutdown_flag:
            server_socket.settimeout(1.0)
            try:
                conn, addr = server_socket.accept()
                print(f"New connection from {addr}")
                
                try:
                    # Receive client choice (register or login)
                    choice_data = receive_full_data(conn)
                    if not choice_data:
                        print("No choice data received")
                        conn.sendall("No choice received".encode('utf-8'))
                        conn.close()
                        continue
                    choice = choice_data.decode('utf-8').strip()
                    print(f"Received choice: {choice}")
                    
                    # Perform first Diffie-Hellman key exchange for authentication
                    private_key, server_public_key = diffie_hellman_exchange()
                    conn.sendall((str(server_public_key) + "\n").encode('utf-8'))
                    print(f"Sent server public key: {server_public_key}")
                    
                    # Receive client public key
                    client_public_key_data = receive_full_data(conn)
                    if not client_public_key_data:
                        print("No public key data received")
                        conn.sendall("No public key received".encode('utf-8'))
                        conn.close()
                        continue
                    try:
                        client_public_key_str = client_public_key_data.decode('utf-8').strip()
                        print(f"Raw client public key data: {client_public_key_str}")
                        if not client_public_key_str.isdigit():
                            raise ValueError("Public key is not a valid integer")
                        client_public_key = int(client_public_key_str)
                        print(f"Decoded client public key: {client_public_key}")
                    except (ValueError, UnicodeDecodeError) as e:
                        print(f"Error decoding client public key: {e}")
                        conn.sendall(f"Invalid public key: {str(e)}".encode('utf-8'))
                        conn.close()
                        continue
                    
                    shared_secret = pow(client_public_key, int.from_bytes(private_key, 'big'), P)
                    K = shared_secret.to_bytes(16, 'big')
                    print(f"Server computed shared secret: {shared_secret}, K: {K.hex()}")
                    
                    # Receive and decrypt authentication data
                    encrypted_data = conn.recv(1024)
                    if not encrypted_data:
                        print("No authentication data received")
                        conn.sendall("No authentication data received".encode('utf-8'))
                        conn.close()
                        continue
                    try:
                        auth_data = json.loads(decrypt_data(K, encrypted_data))
                        username = auth_data['username']
                        print(f"Authentication data: {auth_data}")
                    except (json.JSONDecodeError, ValueError) as e:
                        print(f"Error decoding auth data: {e}")
                        conn.sendall(f"Invalid authentication data: {str(e)}".encode('utf-8'))
                        conn.close()
                        continue
                    
                    if choice == "register":
                        email = auth_data['email']
                        password = auth_data['password']
                        if username in users:
                            response = f"Registration failed: Username {username} already exists"
                        else:
                            users[username] = {
                                'email': email,
                                'password': hashlib.sha256(password.encode()).hexdigest()
                            }
                            response = f"Registration successful for {username}"
                        conn.sendall(response.encode('utf-8'))
                        print(f"Registration response: {response}")
                        conn.close()
                    elif choice == "login":
                        password = auth_data['password']
                        if username in users and users[username]['password'] == hashlib.sha256(password.encode()).hexdigest():
                            response = f"Login successful for {username}"
                            conn.sendall(response.encode('utf-8'))
                            print(f"Login response: {response}")
                            
                            # Perform second Diffie-Hellman key exchange for message encryption
                            private_key, server_public_key = diffie_hellman_exchange()
                            conn.sendall((str(server_public_key) + "\n").encode('utf-8'))
                            print(f"Sent second server public key: {server_public_key}")
                            
                            client_public_key_data = receive_full_data(conn)
                            if not client_public_key_data:
                                print("No second public key data received")
                                conn.sendall("No public key received".encode('utf-8'))
                                conn.close()
                                continue
                            try:
                                client_public_key_str = client_public_key_data.decode('utf-8').strip()
                                print(f"Raw second client public key data: {client_public_key_str}")
                                if not client_public_key_str.isdigit():
                                    raise ValueError("Second public key is not a valid integer")
                                client_public_key = int(client_public_key_str)
                                print(f"Decoded second client public key: {client_public_key}")
                            except (ValueError, UnicodeDecodeError) as e:
                                print(f"Error decoding second public key: {e}")
                                conn.sendall(f"Invalid public key: {str(e)}".encode('utf-8'))
                                conn.close()
                                continue
                            
                            shared_secret = pow(client_public_key, int.from_bytes(private_key, 'big'), P)
                            message_key = derive_message_key(shared_secret, username)
                            print(f"Server computed second shared secret: {shared_secret}")
                            
                            # Start chat session in a new thread
                            chat_thread = threading.Thread(
                                target=chat,
                                args=(conn, message_key, username, addr)
                            )
                            chat_thread.daemon = True
                            chat_thread.start()
                        else:
                            response = "Login failed: Invalid username or password"
                            conn.sendall(response.encode('utf-8'))
                            print(f"Login response: {response}")
                            conn.close()
                    else:
                        conn.sendall("Invalid choice".encode('utf-8'))
                        print("Invalid choice received")
                        conn.close()
                except UnicodeDecodeError as e:
                    print(f"Decode error: {e}")
                    conn.sendall(f"Invalid data format: {str(e)}".encode('utf-8'))
                    conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Connection error: {e}")
    finally:
        if server_socket:
            server_socket.close()
            print("Server socket closed")
        with active_connections_lock:
            for username, client_info in list(active_connections.items()):
                client_info['connection'].close()
                del active_connections[username]

def stop_server():
    global shutdown_flag, server_socket
    shutdown_flag = True
    if server_socket:
        server_socket.close()
        server_socket = None
    print("Server shutdown initiated")

if __name__ == "__main__":
    start_server()