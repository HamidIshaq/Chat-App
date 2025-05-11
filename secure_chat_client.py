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

# Diffie-Hellman public parameters
P = 23  # Choose a large prime number in a real implementation
G = 5   # Primitive root mod P

# Function to perform Diffie-Hellman key exchange
def diffie_hellman_exchange():
    private_key = os.urandom(16)
    public_key = pow(G, int.from_bytes(private_key, 'big'), P)
    return private_key, public_key

# Encrypts the data using AES with key `K`
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv + encrypted_data

def derive_message_key(shared_secret, username):
    key_material = f"{username}{shared_secret}".encode()
    return hashlib.sha256(key_material).digest()[:16]  # AES-128 bit key

def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted_data.decode()

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

# Function to register a new user
def register_user(email, username, password):
    global client_socket, is_connected
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        
        # Send registration choice
        client_socket.sendall("register".encode())
        
        # Perform Diffie-Hellman Key Exchange
        private_key, client_public_key = diffie_hellman_exchange()
        client_socket.sendall(str(client_public_key).encode())
        
        server_public_key = int(client_socket.recv(1024).decode())
        shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
        K = shared_secret.to_bytes(16, 'big')
        
        # Send registration data
        user_data = json.dumps({'email': email, 'username': username, 'password': password})
        encrypted_data = encrypt_data(K, user_data)
        client_socket.sendall(encrypted_data)
        
        # Get registration response
        response = client_socket.recv(1024).decode()
        return response
        
    except Exception as e:
        return f"Registration error: {e}"
    finally:
        if client_socket:
            client_socket.close()
            client_socket = None

# Function to login a user
def login_user(username, password):
    global client_socket, message_key, is_connected
    
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        
        # Send login choice
        client_socket.sendall("login".encode())
        
        # Perform Diffie-Hellman Key Exchange
        private_key, client_public_key = diffie_hellman_exchange()
        client_socket.sendall(str(client_public_key).encode())
        
        server_public_key = int(client_socket.recv(1024).decode())
        shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
        K = shared_secret.to_bytes(16, 'big')
        
        # Send login data
        login_data = json.dumps({'username': username, 'password': password})
        encrypted_data = encrypt_data(K, login_data)
        client_socket.sendall(encrypted_data)
        
        # Get login response
        response = client_socket.recv(1024).decode()
        
        if "successful" in response:
            # Second Diffie-Hellman Key Exchange for Message Encryption
            private_key, client_public_key = diffie_hellman_exchange()
            client_socket.sendall(str(client_public_key).encode())
            
            server_public_key = int(client_socket.recv(1024).decode())
            shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
            message_key = derive_message_key(shared_secret, username)
            
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
        if client_socket:
            client_socket.close()
            client_socket = None
        return f"Login error: {e}"

# Send a message to the server
def send_message(message):
    global client_socket, message_key, is_connected
    
    if not is_connected or not client_socket or not message_key:
        return False
    
    try:
        encrypted_message = encrypt_data(message_key, message)
        client_socket.sendall(encrypted_message)
        on_message_received(message, True)
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

# Disconnect from the server
def disconnect():
    global client_socket, is_connected
    
    if is_connected and client_socket:
        try:
            send_message("bye")
            time.sleep(0.5)  # Give a moment for the message to be sent
        except:
            pass
        
        is_connected = False
        client_socket.close()
        client_socket = None

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

# For testing the client directly
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
            # Start CLI chat for testing
            cli_chat()
    
    # Make sure to disconnect before exiting
    disconnect()