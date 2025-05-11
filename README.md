# Secure Chat Application

This application provides a secure chat platform with end-to-end encryption using Python for the backend and a web-based frontend interface.

## Features

- User authentication (registration and login)
- End-to-end encryption using AES-128
- Diffie-Hellman key exchange for secure key generation
- Web-based frontend interface
- Split server and client views

## Components

1. **Backend**
   - `secure_chat_server.py`: The main server implementation
   - `secure_chat_client.py`: The client communication module
   - `websocket_bridge.py`: Bridge between WebSocket and Python sockets
   - `app.py`: Flask application to serve the web interface

2. **Frontend**
   - `server.html`: Server interface for monitoring connections
   - `client.html`: Client interface for authentication and messaging

## Prerequisites

- Python 3.7 or higher
- Required Python packages:
  - flask
  - websockets
  - pycryptodome (not pycrypto)

## Installation

1. Install required packages:
   ```bash
   pip install flask websockets pycryptodome
   ```

2. Make sure all Python files are in the same directory:
   - secure_chat_server.py
   - secure_chat_client.py
   - websocket_bridge.py
   - app.py

3. Create the HTML files in the same directory:
   - server.html
   - client.html

## Running the Application

1. Start the application:
   ```bash
   python app.py
   ```

2. Open your browser and access:
   - Server interface: http://localhost:5000/
   - Client interface: http://localhost:5000/client

## Usage Instructions

### Server Interface
1. Click "Start Server" to begin listening for connections
2. Monitor the logs and chat messages in the interface
3. Send messages to connected clients using the input field

### Client Interface
1. Choose to register or login
2. If registering, provide email, username, and password
3. If logging in, provide username and password
4. After successful authentication, start chatting with the server

## Security Details

- **Encryption**: AES-128 in CBC mode
- **Key Exchange**: Diffie-Hellman
- **Password Storage**: Hashed with SHA-256 + salt
- **Session Security**: Unique encryption keys per session

## Notes

- This is a development setup and should be modified for production use
- In production, use HTTPS for web