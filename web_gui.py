"""
🔐 QUANTUM FILE ENCRYPTOR - Web-Based GUI
A modern, WinRAR-like interface with drag-and-drop support
"""

import sys
import os
import json
import base64
import webbrowser
import threading
import time
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse
import mimetypes

# Add parent directory
sys.path.insert(0, str(Path(__file__).parent.parent / "QUANTUM_RESISTANT_ENCRYPTION"))

try:
    from quantum_encryption_infinite import InfiniteQuantumEncryption
except ImportError:
    print("Error: quantum_encryption_infinite.py not found!")
    sys.exit(1)

# Configuration
PORT = 8765
KEYS_DIR = Path(__file__).parent / "keys"
MAGIC_HEADER = b"QENC"
VERSION = 1


# ════════════════════════════════════════════════════════════════════════════════
# KEY MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════════

def has_keys():
    return (KEYS_DIR / "public_key.json").exists()

def generate_keys(layers=10):
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    crypto = InfiniteQuantumEncryption(num_layers=layers)
    public_key, private_key = crypto.generate_keypair()
    
    public_data = {
        'encryption_pk': base64.b64encode(public_key['encryption_pk']).decode(),
        'signing_pk': base64.b64encode(public_key['signing_pk']).decode(),
        'num_layers': public_key['num_layers'],
        'version': public_key['version'],
        'created': datetime.now().isoformat(),
    }
    
    private_data = {
        'encryption_sk': base64.b64encode(private_key['encryption_sk']).decode(),
        'signing_sk': base64.b64encode(private_key['signing_sk']).decode(),
        'num_layers': private_key['num_layers'],
        'version': private_key['version'],
        'created': datetime.now().isoformat(),
    }
    
    with open(KEYS_DIR / "public_key.json", 'w') as f:
        json.dump(public_data, f, indent=2)
    with open(KEYS_DIR / "private_key.json", 'w') as f:
        json.dump(private_data, f, indent=2)
    
    return True

def load_public_key():
    try:
        with open(KEYS_DIR / "public_key.json", 'r') as f:
            data = json.load(f)
        return {
            'encryption_pk': base64.b64decode(data['encryption_pk']),
            'signing_pk': base64.b64decode(data['signing_pk']),
            'num_layers': data['num_layers'],
            'version': data['version'],
        }
    except:
        return None

def load_private_key():
    try:
        with open(KEYS_DIR / "private_key.json", 'r') as f:
            data = json.load(f)
        return {
            'encryption_sk': base64.b64decode(data['encryption_sk']),
            'signing_sk': base64.b64decode(data['signing_sk']),
            'num_layers': data['num_layers'],
            'version': data['version'],
        }
    except:
        return None


# ════════════════════════════════════════════════════════════════════════════════
# ENCRYPTION/DECRYPTION
# ════════════════════════════════════════════════════════════════════════════════

def encrypt_file(file_path):
    file_path = Path(file_path)
    public_key = load_public_key()
    if not public_key:
        return False, "No keys found"
    
    output_path = file_path.with_suffix(file_path.suffix + ".qenc")
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    metadata = {
        'original_name': file_path.name,
        'original_size': len(plaintext),
        'encrypted_at': datetime.now().isoformat(),
    }
    metadata_bytes = json.dumps(metadata).encode()
    combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
    
    crypto = InfiniteQuantumEncryption(num_layers=public_key['num_layers'])
    encrypted = crypto.encrypt(combined, public_key)
    
    with open(output_path, 'wb') as f:
        f.write(MAGIC_HEADER)
        f.write(VERSION.to_bytes(2, 'big'))
        f.write(encrypted['num_layers'].to_bytes(4, 'big'))
        ephemeral = encrypted['ephemeral_key']
        f.write(len(ephemeral).to_bytes(4, 'big'))
        f.write(ephemeral)
        enc_data = encrypted['encrypted_data']
        f.write(len(enc_data).to_bytes(8, 'big'))
        f.write(enc_data)
    
    return True, str(output_path)

def decrypt_file(file_path):
    file_path = Path(file_path)
    private_key = load_private_key()
    if not private_key:
        return False, "No private key found"
    
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC_HEADER:
            return False, "Not a valid encrypted file"
        
        version = int.from_bytes(f.read(2), 'big')
        num_layers = int.from_bytes(f.read(4), 'big')
        ephemeral_len = int.from_bytes(f.read(4), 'big')
        ephemeral_key = f.read(ephemeral_len)
        enc_len = int.from_bytes(f.read(8), 'big')
        encrypted_data = f.read(enc_len)
    
    encrypted = {
        'ephemeral_key': ephemeral_key,
        'encrypted_data': encrypted_data,
        'num_layers': num_layers,
        'version': "3.0.0-INFINITE",
    }
    
    crypto = InfiniteQuantumEncryption(num_layers=num_layers)
    decrypted = crypto.decrypt(encrypted, private_key)
    
    metadata_len = int.from_bytes(decrypted[:4], 'big')
    metadata = json.loads(decrypted[4:4+metadata_len].decode())
    plaintext = decrypted[4+metadata_len:]
    
    original_name = metadata.get('original_name', 'decrypted_file')
    output_path = file_path.parent / f"decrypted_{original_name}"
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    return True, str(output_path)


# ════════════════════════════════════════════════════════════════════════════════
# WEB SERVER
# ════════════════════════════════════════════════════════════════════════════════

class EncryptorHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.directory = str(Path(__file__).parent / "web")
        super().__init__(*args, directory=self.directory, **kwargs)
    
    def do_GET(self):
        if self.path == '/':
            self.path = '/index.html'
        elif self.path == '/api/status':
            self.send_json({'hasKeys': has_keys(), 'layers': load_public_key()['num_layers'] if has_keys() else 0})
            return
        return super().do_GET()
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        if self.path == '/api/keygen':
            data = json.loads(post_data)
            layers = data.get('layers', 10)
            success = generate_keys(layers)
            self.send_json({'success': success, 'layers': layers})
        
        elif self.path == '/api/encrypt':
            data = json.loads(post_data)
            file_path = data.get('path')
            success, result = encrypt_file(file_path)
            self.send_json({'success': success, 'result': result})
        
        elif self.path == '/api/decrypt':
            data = json.loads(post_data)
            file_path = data.get('path')
            success, result = decrypt_file(file_path)
            self.send_json({'success': success, 'result': result})
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress logging


def start_server():
    server = HTTPServer(('127.0.0.1', PORT), EncryptorHandler)
    print(f"Server running at http://127.0.0.1:{PORT}")
    server.serve_forever()


# ════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("   🔐 QUANTUM FILE ENCRYPTOR - Web GUI")
    print("=" * 60)
    print()
    
    # Create web directory if needed
    web_dir = Path(__file__).parent / "web"
    web_dir.mkdir(exist_ok=True)
    
    # Start server in thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    time.sleep(0.5)
    
    # Open browser
    print(f"Opening browser at http://127.0.0.1:{PORT}")
    webbrowser.open(f'http://127.0.0.1:{PORT}')
    
    print()
    print("Press Ctrl+C to stop the server...")
    print()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
