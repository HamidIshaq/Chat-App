import socket
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import hashlib

# Diffie-Hellman public parameters
P = 23  # Same as client
G = 5   # Same as client

# Diffie-Hellman Key Exchange
def diffie_hellman_exchange():
    private_key = os.urandom(16)
    public_key = pow(G, int.from_bytes(private_key, 'big'), P)
    return private_key, public_key

# AES decryption
def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted_data.decode()

def derive_message_key(shared_secret, username):
    key_material = f"{username}{shared_secret}".encode()
    return hashlib.sha256(key_material).digest()[:16]  # AES-128 bit key

def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv + encrypted_data

def chat(conn, message_key):
    print("Chat session started. Type 'bye' to end the chat.")
    while True:
        encrypted_message = conn.recv(1024)
        message = decrypt_data(message_key, encrypted_message)
        print(f"Client: {message}")

        if message.lower() == "bye":
            print("Chat ended.")
            break

        response = input("Server: ")
        encrypted_response = encrypt_data(message_key, response)
        conn.sendall(encrypted_response)

# Store or load credentials from JSON
CREDENTIALS_FILE = "creds.json"

def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            return json.load(file)
    return {}

def save_credentials(credentials):
    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(2)
    print("Server is listening on port 12345...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    try:
        credentials = load_credentials()
        
        while True:
            choice = conn.recv(1024).decode().strip().lower()
            
            # Perform Diffie-Hellman Key Exchange
            client_public_key = int(conn.recv(1024).decode())
            private_key, server_public_key = diffie_hellman_exchange()
            conn.sendall(str(server_public_key).encode())

            shared_secret = pow(client_public_key, int.from_bytes(private_key, 'big'), P)
            K = shared_secret.to_bytes(16, 'big')

            if choice == 'register':
                # Registration process
                encrypted_data = conn.recv(1024)
                decrypted_data = json.loads(decrypt_data(K, encrypted_data))
                username = decrypted_data['username']

                if username in credentials:
                    conn.sendall(b"Username already exists. Please try again.")
                else:
                    salt = os.urandom(4).hex()
                    password_hash = hashlib.sha256((decrypted_data['password'] + salt).encode()).hexdigest()
                    credentials[username] = {
                        'email': decrypted_data['email'],
                        'password': password_hash,
                        'salt': salt
                    }
                    save_credentials(credentials)
                    conn.sendall(b"Registration successful. Please log in.")
                    choice = 'login'  # Switch to login mode after registration success

            if choice == 'login':
                # Login process
                encrypted_data = conn.recv(1024)
                decrypted_data = json.loads(decrypt_data(K, encrypted_data))
                username = decrypted_data['username']
                
                if username in credentials:
                    user_data = credentials[username]
                    salt = user_data['salt']
                    hashed_password = hashlib.sha256((decrypted_data['password'] + salt).encode()).hexdigest()

                    if hashed_password == user_data['password']:
                        conn.sendall(b"Login successful.")
                        
                        # Perform second Diffie-Hellman Key Exchange for secure messaging
                        client_public_key = int(conn.recv(1024).decode())
                        private_key, server_public_key = diffie_hellman_exchange()
                        conn.sendall(str(server_public_key).encode())

                        shared_secret = pow(client_public_key, int.from_bytes(private_key, 'big'), P)
                        message_key = derive_message_key(shared_secret, username)

                        # Start secure chat session
                        chat(conn, message_key)
                        break
                    else:
                        conn.sendall(b"Invalid password. Please try again.")
                else:
                    conn.sendall(b"Username not found. Please try again.")

    except Exception as e:
        print("Error:", e)
    finally:
        conn.close()

if __name__ == "__main__":
    start_server()