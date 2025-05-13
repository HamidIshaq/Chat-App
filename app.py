import os
import threading
import time
from flask import Flask, send_from_directory, request, jsonify
import asyncio
import websockets
import socket

# Initialize Flask app
app = Flask(__name__)

# Global variables to track server state
server_thread = None
websocket_server = None

@app.route('/')
def index():
    return send_from_directory('.', 'server.html')

@app.route('/client')
def client():
    return send_from_directory('.', 'client.html')

@app.route('/start_server', methods=['POST'])
def start_server_endpoint():
    global server_thread
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex(('localhost', 12345))
            if result == 0:
                return jsonify({"status": "success", "message": "Server is already running"})
        
        from secure_chat_server import start_server
        server_thread = threading.Thread(target=start_server)
        server_thread.daemon = True
        server_thread.start()
        
        time.sleep(1)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/stop_server', methods=['POST'])
def stop_server_endpoint():
    global server_thread
    try:
        from secure_chat_server import stop_server
        stop_server()
        if server_thread:
            server_thread.join(timeout=2.0)
            server_thread = None
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# WebSocket server for browser communication
async def websocket_handler(websocket, path):
    from websocket_bridge import websocket_handler as bridge_handler
    await bridge_handler(websocket, path)

def start_websocket_server():
    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        # Start the WebSocket server
        server = websockets.serve(websocket_handler, "localhost", 8765)
        loop.run_until_complete(server)
        print("WebSocket server started on ws://localhost:8765")
        loop.run_forever()
    except Exception as e:
        print(f"WebSocket server error: {e}")
    finally:
        loop.close()

if __name__ == "__main__":
    if not os.path.exists("server.html"):
        with open("server.html", "w") as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Chat Server</title>
    <meta http-equiv="refresh" content="0;url=/">
</head>
<body>
    <p>Loading...</p>
</body>
</html>""")
    
    if not os.path.exists("client.html"):
        with open("client.html", "w") as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Chat Client</title>
    <meta http-equiv="refresh" content="0;url=/client">
</head>
<body>
    <p>Loading...</p>
</body>
</html>""")

    websocket_thread = threading.Thread(target=start_websocket_server)
    websocket_thread.daemon = True
    websocket_thread.start()
    
    app.run(host='localhost', port=5000, debug=True, use_reloader=False)