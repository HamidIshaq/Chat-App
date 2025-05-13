import socket
import json
import os
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

def chat(client_socket, message_key):
    print("You can start chatting now. Type 'bye' to end the chat.")
    while True:
        message = input("You: ")
        encrypted_message = encrypt_data(message_key, message)
        client_socket.sendall(encrypted_message)

        if message.lower() == "bye":
            print("Chat ended.")
            break

        encrypted_response = client_socket.recv(1024)
        response = decrypt_data(message_key, encrypted_response)
        print(f"Server: {response}")

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    print("Connected to the server.")

    choice = input("Choose an option: 'register' or 'login': ").strip().lower()
    client_socket.sendall(choice.encode())

    # Perform Diffie-Hellman Key Exchange
    private_key, client_public_key = diffie_hellman_exchange()
    client_socket.sendall(str(client_public_key).encode())

    server_public_key = int(client_socket.recv(1024).decode())
    shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
    K = shared_secret.to_bytes(16, 'big')

    while True:
        if choice == 'register':
            # Registration process
            email = input("Enter email: ")
            username = input("Enter username: ")
            password = input("Enter password: ")

            user_data = json.dumps({'email': email, 'username': username, 'password': password})
            encrypted_data = encrypt_data(K, user_data)
            client_socket.sendall(encrypted_data)
            response = client_socket.recv(1024).decode()
            print(response)

            if "successful" in response:
                choice = 'login'
            else:
                choice = input("Please try again. Choose 'register' or 'login': ").strip().lower()
                client_socket.sendall(choice.encode())
                continue

        if choice == 'login':
            # Login process
            username = input("Enter username: ")
            password = input("Enter password: ")

            login_data = json.dumps({'username': username, 'password': password})
            encrypted_data = encrypt_data(K, login_data)
            client_socket.sendall(encrypted_data)
            
            response = client_socket.recv(1024).decode()
            print(response)

            if "successful" in response:
                # Second Diffie-Hellman Key Exchange for Message Encryption
                private_key, client_public_key = diffie_hellman_exchange()
                client_socket.sendall(str(client_public_key).encode())

                server_public_key = int(client_socket.recv(1024).decode())
                shared_secret = pow(server_public_key, int.from_bytes(private_key, 'big'), P)
                message_key = derive_message_key(shared_secret, username)

                # Start secure chat session
                chat(client_socket, message_key)
                break
            else:
                choice = input("Please try again. Choose 'register' or 'login': ").strip().lower()
                client_socket.sendall(choice.encode())

    client_socket.close()

if __name__ == "__main__":
    start_client()