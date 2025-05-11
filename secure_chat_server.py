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
server_socket = None

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

def chat(conn, message_key, username, client_address):
    global active_connections
    
    try:
        print(f"Chat session started with {username}. Type 'bye' to end the chat.")
        
        # Store connection in active connections
        active_connections[username] = {
            'connection': conn,
            'message_key': message_key,
            'address': client_address
        }
        
        # Broadcast connection status to WebSocket clients
        broadcast_status_update(username, client_address, True)
        
        while True:
            try:
                encrypted_message = conn.recv(1024)
                if not encrypted_message:
                    break
                    
                message = decrypt_data(message_key, encrypted_message)
                print(f"Client ({username}): {message}")
                
                # Broadcast message to WebSocket clients
                broadcast_message(username, message)

                if message.lower() == "bye":
                    print(f"Chat with {username} ended.")
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break
    finally:
        # Remove from active connections when session ends
        if username in active_connections:
            del active_connections[username]
        
        # Broadcast disconnection
        broadcast_status_update(username, client_address, False)
        conn.close()

# Send a message from server to client
def send_server_message(username, message):
    if username in active_connections:
        client_info = active_connections[username]
        encrypted_response = encrypt_data(client_info['message_key'], message)
        client_info['connection'].sendall(encrypted_response)
        return True
    return False

# Broadcast status updates to WebSocket clients
def broadcast_status_update(username, client_address, connected=True):
    # This function will be overridden by websocket_bridge
    pass

# Broadcast message to WebSocket clients
def broadcast_message(username, message):
    # This function will be overridden by websocket_bridge
    pass