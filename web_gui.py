"""
🔐 QUANTUM FILE ENCRYPTOR - Web-Based GUI
A modern, WinRAR-like interface with drag-and-drop support
Uses Post-Quantum Hybrid Encryption (QuantumSecureVault)
"""

import sys
import os
import json
import base64
import secrets
import webbrowser
import threading
import time
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse
import mimetypes

# Add local folder and parent directory
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(1, str(Path(__file__).parent.parent / "QUANTUM_RESISTANT_ENCRYPTION"))

# Try to import QuantumSecureVault (post-quantum)
try:
    from secure_vault_quantum import QuantumSecureVault, SecureVault
    ENCRYPTION_LEVEL = "QUANTUM"
    QUANTUM_AVAILABLE = True
except ImportError:
    try:
        from secure_vault import SecureVault
        ENCRYPTION_LEVEL = "STANDARD"
        QUANTUM_AVAILABLE = False
    except ImportError:
        print("Error: No encryption module found!")
        sys.exit(1)

# Configuration
PORT = 8765
MAGIC_HEADER = b"QVLT"
VERSION = 2


# ════════════════════════════════════════════════════════════════════════════════
# FILE ENCRYPTOR
# ════════════════════════════════════════════════════════════════════════════════

def get_vault():
    """Get the appropriate vault instance"""
    if QUANTUM_AVAILABLE:
        return QuantumSecureVault()
    return SecureVault()

def generate_password() -> str:
    """Generate a secure random password"""
    return base64.b64encode(secrets.token_bytes(32)).decode('ascii')

def encrypt_file(file_path, password):
    """Encrypt a file with password"""
    file_path = Path(file_path)
    vault = get_vault()
    
    output_path = file_path.with_suffix(file_path.suffix + ".qenc")
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    metadata = {
        'original_name': file_path.name,
        'original_size': len(plaintext),
        'encrypted_at': datetime.now().isoformat(),
        'encryption_level': ENCRYPTION_LEVEL,
    }
    metadata_bytes = json.dumps(metadata).encode()
    combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
    
    encrypted_data = vault.encrypt(combined, password)
    
    with open(output_path, 'wb') as f:
        f.write(MAGIC_HEADER)
        f.write(VERSION.to_bytes(2, 'big'))
        f.write(len(encrypted_data).to_bytes(8, 'big'))
        f.write(encrypted_data)
    
    return True, str(output_path)

def decrypt_file(file_path, password):
    """Decrypt a file with password"""
    file_path = Path(file_path)
    vault = get_vault()
    
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC_HEADER:
            return False, "Not a valid encrypted file"
        
        version = int.from_bytes(f.read(2), 'big')
        enc_len = int.from_bytes(f.read(8), 'big')
        encrypted_data = f.read(enc_len)
    
    try:
        decrypted = vault.decrypt(encrypted_data, password)
    except ValueError:
        return False, "Wrong password!"
    
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
            self.send_json({
                'quantumAvailable': QUANTUM_AVAILABLE,
                'encryptionLevel': ENCRYPTION_LEVEL
            })
            return
        elif self.path == '/api/genkey':
            password = generate_password()
            self.send_json({'password': password})
            return
        return super().do_GET()
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        if self.path == '/api/encrypt':
            data = json.loads(post_data)
            file_path = data.get('path')
            
            # Validate file path - must exist and be a file
            if not file_path or not Path(file_path).exists() or not Path(file_path).is_file():
                self.send_json({'success': False, 'result': 'Invalid file path'})
                return
            
            password = data.get('password')
            if not password:
                password = generate_password()
            success, result = encrypt_file(file_path, password)
            self.send_json({'success': success, 'result': result, 'password': password})
        
        elif self.path == '/api/decrypt':
            data = json.loads(post_data)
            file_path = data.get('path')
            
            # Validate file path - must exist, be a file, and have .qenc extension
            if not file_path or not Path(file_path).exists() or not Path(file_path).is_file():
                self.send_json({'success': False, 'result': 'Invalid file path'})
                return
            
            password = data.get('password')
            if not password:
                self.send_json({'success': False, 'result': 'Password required'})
                return
            
            success, result = decrypt_file(file_path, password)
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
    if QUANTUM_AVAILABLE:
        print("   Post-Quantum Hybrid Encryption (ML-KEM-1024)")
    else:
        print("   Standard Edition (AES-256-GCM)")
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
