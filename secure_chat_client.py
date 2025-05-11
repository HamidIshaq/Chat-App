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

# Diffie-Hellman public parameters (2048-bit MODP group from RFC 3526)
P = 23
G = 2

# Function to perform Diffie-Hellman key exchange
def diffie_hellman_exchange():
    private_key = os.urandom(16)
    public_key = pow(G, int.from_bytes(private_key, 'big'), P)
    if not isinstance(public_key, int) or public_key <= 0:
        raise ValueError("Invalid public key generated")
    print(f"Client generated private key: {private_key.hex()}, public key: {public_key}")
    return private_key, public_key

# Encrypts the data using AES with key `K`
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    print(f"Client encrypting data: {data}, key: {key.hex()}, iv: {iv.hex()}")
    return iv + encrypted_data

def derive_message_key(shared_secret, username):
    key_material = f"{username}{shared_secret}".encode()
    key = hashlib.sha256(key_material).digest()[:16]  # AES-128 bit key
    print(f"Client derived message key: {key.hex()} for username: {username}")
    return key

def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    print(f"Client decrypting data, key: {key.hex()}, iv: {iv.hex()}, decrypted: {decrypted_data.decode()}")
    return decrypted_data.decode()

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
        print("Client timeout while receiving data")
    finally:
        conn.settimeout(None)
    return data

# Global variables for client connection
client_socket = None
message_key = None
is_connected = False
message_handlers = []

# Register a message handler
def register_message_handler(handler):
    message_handlers.append(handler)

# Callback when a message is received
def on_message_received(message, is_client=False):
    for handler in message_handlers:
        handler(message, is_client)

# Function to handle incoming messages in a separate thread
def message_receiver():
    global is_connected, client_socket, message_key
    
    while is_connected and client_socket and message_key:
        try:
            encrypted_response = client_socket.recv(1024)
            if not encrypted_response:
                break
                
            response = decrypt_data(message_key, encrypted_response)
            on_message_received(response, False)
            
            if response.lower() == "bye":
                print("Server ended the chat.")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    
    is_connected = False
    if client_socket:
        client_socket.close()
        client_socket = None
        print("Client socket closed in message receiver")

# Function to register a new user
def register_user(email, username, password):
    global client_socket, is_connected
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        print("Client connected to server for registration")
        
        # Send registration choice
        client_socket.sendall("register\n".encode('utf-8'))
        print("Client sent choice: register")
        
        # Perform Diffie-Hellman Key Exchange
        private_key, client_public_key = diffie_hellman_exchange()
        client_socket.sendall((str(client_public_key) + "\n").encode('utf-8'))
        print(f"Client sent public key: {client_public_key}")
        
        server_public_key_data = receive_full_data(client_socket)
        if not server_public_key_data:
            print("Client received no server public key")
            client_socket.close()
            client_socket = None
            return "Registration error: No server public key received"
        try:
            server_public_key_str = server_public_key_data.decode('utf-8').strip()
            print(f"Client received raw server public key: {server_public_key_str}")
            if not server_public_key_str.isdigit():
                raise ValueError("Server public key is not a valid integer")
            server_public_key = int(server_public_key_str)
            print(f"Client decoded server public key: {server_public_key}")
        except (ValueError, UnicodeDecodeError) as e:
            print(f"Client error decoding server public key: {e}")
            client_socket.close()
            client_socket = None
            return f"Registration error: Invalid server public key ({e})"
        
        shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
        K = shared_secret.to_bytes(16, 'big')
        print(f"Client computed shared secret: {shared_secret}, K: {K.hex()}")
        
        # Send registration data
        user_data = json.dumps({'email': email, 'username': username, 'password': password})
        encrypted_data = encrypt_data(K, user_data)
        client_socket.sendall(encrypted_data)
        print(f"Client sent encrypted registration data: {user_data}")
        
        # Get registration response
        response_data = client_socket.recv(1024)
        response = response_data.decode('utf-8')
        print(f"Client received registration response: {response}")
        return response
        
    except Exception as e:
        print(f"Client registration error: {e}")
        return f"Registration error: {e}"
    finally:
        if client_socket:
            client_socket.close()
            client_socket = None
            print("Client closed socket for registration")

# Function to login a user
def login_user(username, password):
    global client_socket, message_key, is_connected
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        print("Client connected to server for login")
        
        # Send login choice
        client_socket.sendall("login\n".encode('utf-8'))
        print("Client sent choice: login")
        
        # Perform Diffie-Hellman Key Exchange
        private_key, client_public_key = diffie_hellman_exchange()
        client_socket.sendall((str(client_public_key) + "\n").encode('utf-8'))
        print(f"Client sent public key: {client_public_key}")
        
        server_public_key_data = receive_full_data(client_socket)
        if not server_public_key_data:
            print("Client received no server public key")
            client_socket.close()
            client_socket = None
            return "Login error: No server public key received"
        try:
            server_public_key_str = server_public_key_data.decode('utf-8').strip()
            print(f"Client received raw server public key: {server_public_key_str}")
            if not server_public_key_str.isdigit():
                raise ValueError("Server public key is not a valid integer")
            server_public_key = int(server_public_key_str)
            print(f"Client decoded server public key: {server_public_key}")
        except (ValueError, UnicodeDecodeError) as e:
            print(f"Client error decoding server public key: {e}")
            client_socket.close()
            client_socket = None
            return f"Login error: Invalid server public key ({e})"
        
        shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
        K = shared_secret.to_bytes(16, 'big')
        print(f"Client computed shared secret: {shared_secret}, K: {K.hex()}")
        
        # Send login data
        login_data = json.dumps({'username': username, 'password': password})
        encrypted_data = encrypt_data(K, login_data)
        client_socket.sendall(encrypted_data)
        print(f"Client sent encrypted login data: {login_data}")
        
        # Get login response
        response_data = client_socket.recv(1024)
        response = response_data.decode('utf-8')
        print(f"Client received login response: {response}")
        
        if "successful" in response:
            # Second Diffie-Hellman Key Exchange for Message Encryption
            private_key, client_public_key = diffie_hellman_exchange()
            client_socket.sendall((str(client_public_key) + "\n").encode('utf-8'))
            print(f"Client sent second public key: {client_public_key}")
            
            server_public_key_data = receive_full_data(client_socket)
            if not server_public_key_data:
                print("Client received no second server public key")
                client_socket.close()
                client_socket = None
                return "Login error: No second server public key received"
            try:
                server_public_key_str = server_public_key_data.decode('utf-8').strip()
                print(f"Client received raw second server public key: {server_public_key_str}")
                if not server_public_key_str.isdigit():
                    raise ValueError("Second server public key is not a valid integer")
                server_public_key = int(server_public_key_str)
                print(f"Client decoded second server public key: {server_public_key}")
            except (ValueError, UnicodeDecodeError) as e:
                print(f"Client error decoding second server public key: {e}")
                client_socket.close()
                client_socket = None
                return f"Login error: Invalid server public key for message encryption ({e})"
            
            shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
            message_key = derive_message_key(shared_secret, username)
            print(f"Client computed second shared secret: {shared_secret}")
            
            # Set connected flag
            is_connected = True
            
            # Start message receiver thread
            receiver_thread = threading.Thread(target=message_receiver, daemon=True)
            receiver_thread.start()
            
            return response
        else:
            client_socket.close()
            client_socket = None
            return response
        
    except Exception as e:
        print(f"Client login error: {e}")
        if client_socket:
            client_socket.close()
            client_socket = None
        return f"Login error: {e}"

# Send a message to the server
def send_message(message):
    global client_socket, message_key, is_connected
    
    if not is_connected or not client_socket or not message_key:
        print("Client cannot send message: Not connected")
        return False
    
    try:
        encrypted_message = encrypt_data(message_key, message)
        client_socket.sendall(encrypted_message)
        on_message_received(message, True)
        print(f"Client sent message: {message}")
        return True
    except Exception as e:
        print(f"Client error sending message: {e}")
        return False

# Disconnect from the server
def disconnect():
    global client_socket, is_connected
    
    if is_connected and client_socket:
        try:
            send_message("bye")
            time.sleep(0.5)
        except:
            pass
        
        is_connected = False
        client_socket.close()
        client_socket = None
        print("Client disconnected from server")

# Command-line interface for testing
def cli_chat():
    print("You can start chatting now. Type 'bye' to end the chat.")
    while True:
        message = input("You: ")
        if not send_message(message):
            print("Failed to send message. You may be disconnected.")
            break
            
        if message.lower() == "bye":
            print("Chat ended.")
            break

if __name__ == "__main__":
    choice = input("Choose an option: 'register' or 'login': ").strip().lower()
    
    if choice == 'register':
        email = input("Enter email: ")
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        response = register_user(email, username, password)
        print(response)
        
        if "successful" in response:
            choice = 'login'
    
    if choice == 'login':
        username = input("Enter username: ")
        password = input("Enter password: ")
        
        response = login_user(username, password)
        print(response)
        
        if "successful" in response:
            cli_chat()
    
    disconnect()