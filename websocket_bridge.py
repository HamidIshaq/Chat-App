import asyncio
import websockets
import socket
import threading
import json
import ssl
import os
from flask import Flask, send_from_directory, request, jsonify
import time

# Flask app for serving the frontend
app = Flask(__name__)

# Global variables to track server state
server_process = None
server_socket = None
connected_websockets = set()
server_thread = None
client_handler_thread = None

# Mutex for thread safety
lock = threading.Lock()

# Store running server socket for client connections
_server_socket = None

# Path to static files (HTML, CSS, JS)
@app.route('/')
def index():
    return send_from_directory('.', 'server.html')

@app.route('/client')
def client():
    return send_from_directory('.', 'client.html')

@app.route('/start_server', methods=['POST'])
def start_server_endpoint():
    global server_thread
    
    if server_thread and server_thread.is_alive():
        return jsonify({"status": "error", "message": "Server is already running"})
    
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Give it a moment to start
    time.sleep(1)
    
    return jsonify({"status": "success"})

@app.route('/stop_server', methods=['POST'])
def stop_server_endpoint():
    global server_thread
    
    if not server_thread or not server_thread.is_alive():
        return jsonify({"status": "error", "message": "Server is not running"})
    
    # Implement server shutdown logic here
    # This is a placeholder; you'll need to implement how to stop your server
    
    return jsonify({"status": "success"})

# Create an event loop for the WebSocket server
def create_event_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop

# WebSocket handler for client connections
async def websocket_handler(websocket, path):
    # Keep track of connected clients
    connected_websockets.add(websocket)
    
    try:
        async for message in websocket:
            data = json.loads(message)
            print(f"Received WebSocket message: {data}")
            
            if data['type'] == 'login' or data['type'] == 'register':
                # Handle authentication
                await handle_authentication(websocket, data)
            elif data['type'] == 'chat_message':
                # Handle chat message
                await handle_chat_message(websocket, data)
            elif data['type'] == 'server_message':
                # Handle server message (from server UI to client)
                await handle_server_message(data)
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        connected_websockets.remove(websocket)

# Handle authentication requests
async def handle_authentication(websocket, data):
    try:
        # Use our secure_chat_client functions instead of direct socket
        if data['type'] == 'register':
            # Handle registration
            from secure_chat_client import register_user
            response = register_user(
                data.get('email', ''),
                data['username'],
                data['password']
            )
            
            if "successful" in response:
                await websocket.send(json.dumps({
                    'type': 'auth_response',
                    'status': 'success',
                    'message': response
                }))
            else:
                await websocket.send(json.dumps({
                    'type': 'auth_response',
                    'status': 'error',
                    'message': response
                }))
        else:
            # Handle login
            from secure_chat_client import login_user, register_message_handler
            
            # Register a message handler to forward messages to WebSocket
            async def message_handler(message, is_client):
                if websocket.open:
                    await websocket.send(json.dumps({
                        'type': 'chat_message',
                        'message': message,
                        'from': 'client' if is_client else 'server'
                    }))
            
            # Create a wrapper for the async message handler
            def message_handler_wrapper(message, is_client):
                asyncio.run_coroutine_threadsafe(
                    message_handler(message, is_client),
                    asyncio.get_event_loop()
                )
            
            # Register our message handler
            register_message_handler(message_handler_wrapper)
            
            # Attempt to login
            response = login_user(data['username'], data['password'])
            
            if "successful" in response:
                await websocket.send(json.dumps({
                    'type': 'auth_response',
                    'status': 'success',
                    'message': response
                }))
            else:
                await websocket.send(json.dumps({
                    'type': 'auth_response',
                    'status': 'error',
                    'message': response
                }))
    except Exception as e:
        await websocket.send(json.dumps({
            'type': 'auth_response',
            'status': 'error',
            'message': f"Failed to authenticate: {str(e)}"
        }))

# Handle chat messages from client to server
async def handle_chat_message(websocket, data):
    from secure_chat_client import send_message, is_connected
    
    if is_connected:
        success = send_message(data['message'])
        if not success:
            await websocket.send(json.dumps({
                'type': 'chat_message',
                'message': 'Failed to send message. Connection might be lost.',
                'from': 'system'
            }))
    else:
        await websocket.send(json.dumps({
            'type': 'chat_message',
            'message': 'Not connected to server. Please login first.',
            'from': 'system'
        }))

# Handle messages from server UI to client
async def handle_server_message(data):
    # Broadcast server message to all connected clients
    if connected_websockets:
        await asyncio.gather(
            *[ws.send(json.dumps({
                'type': 'chat_message',
                'message': data['message'],
                'from': 'server'
            })) for ws in connected_websockets]
        )

# Thread function to handle socket communication between client and server
def client_communication_handler(client_socket, websocket):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Set up a reader thread for the client socket
        while True:
            # Receive data from the Python backend
            data = client_socket.recv(1024)
            if not data:
                break
                
            # Forward the data to the WebSocket client
            # In production, this would need to decode the encrypted data
            message = data.decode('utf-8')
            
            asyncio.run_coroutine_threadsafe(
                websocket.send(json.dumps({
                    'type': 'chat_message',
                    'message': message,
                    'from': 'server'
                })),
                loop
            )
            
    except Exception as e:
        print(f"Error in client communication: {e}")
    finally:
        client_socket.close()

# Start the secure chat server
def start_server():
    try:
        # Import your server implementation
        from secure_chat_server import start_server
        
        # Start the server in a separate thread
        server_thread = threading.Thread(target=start_server)
        server_thread.daemon = True
        server_thread.start()
        
        print("Server started successfully")
        return True
    except Exception as e:
        print(f"Failed to start server: {e}")
        return False

# Start WebSocket server
def start_websocket_server():
    loop = create_event_loop()
    start_server = websockets.serve(websocket_handler, "localhost", 8765)
    loop.run_until_complete(start_server)
    loop.run_forever()

if __name__ == "__main__":
    # Start WebSocket server in a separate thread
    websocket_thread = threading.Thread(target=start_websocket_server)
    websocket_thread.daemon = True
    websocket_thread.start()
    
    # Start Flask app
    app.run(host='localhost', port=5000, debug=True, use_reloader=False)