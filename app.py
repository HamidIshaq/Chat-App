import os
import threading
import time
from flask import Flask, send_from_directory, request, jsonify
import asyncio
import websockets

# Initialize Flask app
app = Flask(__name__)

# Global variables to track server state
server_process = None
websocket_server = None

@app.route('/')
def index():
    return send_from_directory('.', 'server.html')

@app.route('/client')
def client():
    return send_from_directory('.', 'client.html')

@app.route('/start_server', methods=['POST'])
def start_server_endpoint():
    # Start the secure chat server in a separate thread
    from secure_chat_server import start_server
    
    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Give it a moment to start
    time.sleep(1)
    
    return jsonify({"status": "success"})

@app.route('/stop_server', methods=['POST'])
def stop_server_endpoint():
    # This would require modifying your server code to have a clean shutdown method
    return jsonify({"status": "success"})

# WebSocket server for browser communication
async def websocket_handler(websocket, path):
    from websocket_bridge import websocket_handler as bridge_handler
    await bridge_handler(websocket, path)

def start_websocket_server():
    # Create a new event loop for the websocket server
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Start the websocket server
    start_server = websockets.serve(websocket_handler, "localhost", 8765)
    loop.run_until_complete(start_server)
    loop.run_forever()

if __name__ == "__main__":
    # Make sure HTML files exist
    if not os.path.exists("server.html"):
        with open("server.html", "w") as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Chat Server</title>
    <!-- Page will be replaced with full server.html content -->
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
    <!-- Page will be replaced with full client.html content -->
    <meta http-equiv="refresh" content="0;url=/client">
</head>
<body>
    <p>Loading...</p>
</body>
</html>""")

    # Start WebSocket server in a separate thread
    websocket_thread = threading.Thread(target=start_websocket_server)
    websocket_thread.daemon = True
    websocket_thread.start()
    
    # Start Flask app
    app.run(host='localhost', port=5000, debug=True, use_reloader=False)