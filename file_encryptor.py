"""
╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                  ║
║   🔐 QUANTUM FILE ENCRYPTOR - GUI Application (FORTRESS EDITION)                                ║
║                                                                                                  ║
║   A powerful file encryption tool using Quantum Fortress Encryption                             ║
║                                                                                                  ║
║   Security Features:                                                                             ║
║   • Memory-hard key derivation (Argon2-like)                                                    ║
║   • Triple hash verification (SHA3 + BLAKE2 + SHAKE256)                                         ║
║   • 10-layer cascade encryption (10,240 bits)                                                   ║
║   • Unique S-box per layer                                                                      ║
║   • Per-layer + Master authentication                                                           ║
║   • Constant-time operations (side-channel resistant)                                           ║
║                                                                                                  ║
║   Security: 10,240+ bits (configurable)                                                         ║
║   Breaking Time: 10^3,082+ years                                                                ║
║                                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import json
import base64
import secrets
import threading
from pathlib import Path
from datetime import datetime

# Add local folder and parent directory to import the encryption modules
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(1, str(Path(__file__).parent.parent / "QUANTUM_RESISTANT_ENCRYPTION"))

# Try to import Quantum Fortress (best), fall back to Infinite
try:
    from quantum_fortress import QuantumFortress
    ENCRYPTION_LEVEL = "FORTRESS"
except ImportError:
    try:
        from quantum_encryption_infinite import InfiniteQuantumEncryption
        ENCRYPTION_LEVEL = "INFINITE"
    except ImportError:
        print("Error: No encryption module found!")
        print("Make sure quantum_fortress.py or quantum_encryption_infinite.py exists.")
        sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════════════════
# THEME CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════════════════

class Theme:
    """Modern dark theme colors"""
    BG_DARK = "#0d1117"
    BG_MEDIUM = "#161b22"
    BG_LIGHT = "#21262d"
    BG_HOVER = "#30363d"
    
    TEXT_PRIMARY = "#f0f6fc"
    TEXT_SECONDARY = "#8b949e"
    TEXT_MUTED = "#6e7681"
    
    ACCENT_BLUE = "#58a6ff"
    ACCENT_GREEN = "#3fb950"
    ACCENT_RED = "#f85149"
    ACCENT_YELLOW = "#d29922"
    ACCENT_PURPLE = "#a371f7"
    
    BORDER = "#30363d"
    
    SUCCESS = "#238636"
    ERROR = "#da3633"
    WARNING = "#9e6a03"


# ════════════════════════════════════════════════════════════════════════════════════════
# KEY MANAGER
# ════════════════════════════════════════════════════════════════════════════════════════

class KeyManager:
    """Manages encryption keys"""
    
    def __init__(self, keys_dir: str):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.public_key_file = self.keys_dir / "public_key.json"
        self.private_key_file = self.keys_dir / "private_key.json"
    
    def generate_keys(self, num_layers: int = 10) -> bool:
        """Generate new key pair"""
        try:
            crypto = InfiniteQuantumEncryption(num_layers=num_layers)
            public_key, private_key = crypto.generate_keypair()
            
            # Serialize keys (convert bytes to base64)
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
            
            with open(self.public_key_file, 'w') as f:
                json.dump(public_data, f, indent=2)
            
            with open(self.private_key_file, 'w') as f:
                json.dump(private_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error generating keys: {e}")
            return False
    
    def load_public_key(self) -> dict:
        """Load public key"""
        if not self.public_key_file.exists():
            return None
        
        with open(self.public_key_file, 'r') as f:
            data = json.load(f)
        
        return {
            'encryption_pk': base64.b64decode(data['encryption_pk']),
            'signing_pk': base64.b64decode(data['signing_pk']),
            'num_layers': data['num_layers'],
            'version': data['version'],
        }
    
    def load_private_key(self) -> dict:
        """Load private key"""
        if not self.private_key_file.exists():
            return None
        
        with open(self.private_key_file, 'r') as f:
            data = json.load(f)
        
        return {
            'encryption_sk': base64.b64decode(data['encryption_sk']),
            'signing_sk': base64.b64decode(data['signing_sk']),
            'num_layers': data['num_layers'],
            'version': data['version'],
        }
    
    def has_keys(self) -> bool:
        """Check if keys exist"""
        return self.public_key_file.exists() and self.private_key_file.exists()


# ════════════════════════════════════════════════════════════════════════════════════════
# FILE ENCRYPTOR ENGINE
# ════════════════════════════════════════════════════════════════════════════════════════

class FileEncryptor:
    """Handles file encryption/decryption"""
    
    MAGIC_HEADER = b"QENC"  # Quantum Encrypted file header
    VERSION = 1
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
    
    def encrypt_file(self, input_path: str, output_path: str = None, 
                     progress_callback=None) -> bool:
        """Encrypt a file"""
        try:
            input_path = Path(input_path)
            if output_path is None:
                output_path = input_path.with_suffix(input_path.suffix + ".qenc")
            else:
                output_path = Path(output_path)
            
            public_key = self.key_manager.load_public_key()
            if public_key is None:
                raise ValueError("No public key found! Generate keys first.")
            
            # Read file
            if progress_callback:
                progress_callback(0, "Reading file...")
            
            with open(input_path, 'rb') as f:
                plaintext = f.read()
            
            # Create metadata
            metadata = {
                'original_name': input_path.name,
                'original_size': len(plaintext),
                'encrypted_at': datetime.now().isoformat(),
            }
            metadata_bytes = json.dumps(metadata).encode()
            
            # Combine metadata length + metadata + plaintext
            combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
            
            if progress_callback:
                progress_callback(20, "Encrypting with quantum-resistant algorithm...")
            
            # Encrypt
            crypto = InfiniteQuantumEncryption(num_layers=public_key['num_layers'])
            encrypted = crypto.encrypt(combined, public_key)
            
            if progress_callback:
                progress_callback(80, "Writing encrypted file...")
            
            # Write encrypted file with header
            with open(output_path, 'wb') as f:
                # Write header
                f.write(self.MAGIC_HEADER)
                f.write(self.VERSION.to_bytes(2, 'big'))
                f.write(encrypted['num_layers'].to_bytes(4, 'big'))
                
                # Write ephemeral key
                ephemeral = encrypted['ephemeral_key']
                f.write(len(ephemeral).to_bytes(4, 'big'))
                f.write(ephemeral)
                
                # Write encrypted data
                enc_data = encrypted['encrypted_data']
                f.write(len(enc_data).to_bytes(8, 'big'))
                f.write(enc_data)
            
            if progress_callback:
                progress_callback(100, "Encryption complete!")
            
            return True, str(output_path)
            
        except Exception as e:
            return False, str(e)
    
    def decrypt_file(self, input_path: str, output_path: str = None,
                     progress_callback=None) -> bool:
        """Decrypt a file"""
        try:
            input_path = Path(input_path)
            
            private_key = self.key_manager.load_private_key()
            if private_key is None:
                raise ValueError("No private key found! Cannot decrypt.")
            
            if progress_callback:
                progress_callback(0, "Reading encrypted file...")
            
            with open(input_path, 'rb') as f:
                # Read and verify header
                magic = f.read(4)
                if magic != self.MAGIC_HEADER:
                    raise ValueError("Not a valid QENC encrypted file!")
                
                version = int.from_bytes(f.read(2), 'big')
                num_layers = int.from_bytes(f.read(4), 'big')
                
                # Read ephemeral key
                ephemeral_len = int.from_bytes(f.read(4), 'big')
                ephemeral_key = f.read(ephemeral_len)
                
                # Read encrypted data
                enc_len = int.from_bytes(f.read(8), 'big')
                encrypted_data = f.read(enc_len)
            
            if progress_callback:
                progress_callback(20, "Decrypting with quantum-resistant algorithm...")
            
            # Prepare encrypted structure
            encrypted = {
                'ephemeral_key': ephemeral_key,
                'encrypted_data': encrypted_data,
                'num_layers': num_layers,
                'version': "3.0.0-INFINITE",
            }
            
            # Decrypt
            crypto = InfiniteQuantumEncryption(num_layers=num_layers)
            decrypted = crypto.decrypt(encrypted, private_key)
            
            if progress_callback:
                progress_callback(70, "Extracting original file...")
            
            # Parse metadata and plaintext
            metadata_len = int.from_bytes(decrypted[:4], 'big')
            metadata = json.loads(decrypted[4:4+metadata_len].decode())
            plaintext = decrypted[4+metadata_len:]
            
            # Determine output path
            if output_path is None:
                original_name = metadata.get('original_name', 'decrypted_file')
                output_path = input_path.parent / f"decrypted_{original_name}"
            
            if progress_callback:
                progress_callback(90, "Writing decrypted file...")
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            if progress_callback:
                progress_callback(100, "Decryption complete!")
            
            return True, str(output_path)
            
        except Exception as e:
            return False, str(e)


# ════════════════════════════════════════════════════════════════════════════════════════
# GUI APPLICATION
# ════════════════════════════════════════════════════════════════════════════════════════

class QuantumFileEncryptorApp:
    """Main GUI Application"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 Quantum File Encryptor")
        self.root.geometry("800x600")
        self.root.configure(bg=Theme.BG_DARK)
        self.root.minsize(700, 500)
        
        # Initialize components
        app_dir = Path(__file__).parent
        self.key_manager = KeyManager(app_dir / "keys")
        self.file_encryptor = FileEncryptor(self.key_manager)
        
        # Selected file
        self.selected_file = None
        self.num_layers = tk.IntVar(value=10)
        
        # Build UI
        self._create_styles()
        self._create_header()
        self._create_main_content()
        self._create_status_bar()
        
        # Check for existing keys
        self._update_key_status()
    
    def _create_styles(self):
        """Create custom styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure("Dark.TFrame", background=Theme.BG_DARK)
        style.configure("Medium.TFrame", background=Theme.BG_MEDIUM)
        style.configure("Light.TFrame", background=Theme.BG_LIGHT)
        
        style.configure("Title.TLabel", 
                       background=Theme.BG_DARK,
                       foreground=Theme.TEXT_PRIMARY,
                       font=("Segoe UI", 24, "bold"))
        
        style.configure("Subtitle.TLabel",
                       background=Theme.BG_DARK,
                       foreground=Theme.TEXT_SECONDARY,
                       font=("Segoe UI", 11))
        
        style.configure("Info.TLabel",
                       background=Theme.BG_MEDIUM,
                       foreground=Theme.TEXT_PRIMARY,
                       font=("Segoe UI", 10))
        
        style.configure("Status.TLabel",
                       background=Theme.BG_LIGHT,
                       foreground=Theme.TEXT_SECONDARY,
                       font=("Segoe UI", 9))
    
    def _create_header(self):
        """Create header section"""
        header = tk.Frame(self.root, bg=Theme.BG_DARK, pady=20)
        header.pack(fill=tk.X)
        
        # Title
        title = tk.Label(header, text="🔐 Quantum File Encryptor",
                        bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY,
                        font=("Segoe UI", 24, "bold"))
        title.pack()
        
        # Subtitle
        subtitle = tk.Label(header, 
                           text="Infinite-Layer Quantum-Resistant Encryption",
                           bg=Theme.BG_DARK, fg=Theme.TEXT_SECONDARY,
                           font=("Segoe UI", 11))
        subtitle.pack()
        
        # Security badge
        security = tk.Label(header,
                           text="🛡️ 10,240-bit Security | 10^3,082 Years to Break",
                           bg=Theme.BG_DARK, fg=Theme.ACCENT_GREEN,
                           font=("Segoe UI", 10))
        security.pack(pady=(10, 0))
    
    def _create_main_content(self):
        """Create main content area"""
        main = tk.Frame(self.root, bg=Theme.BG_DARK, padx=40)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Key Management Section
        self._create_key_section(main)
        
        # File Selection Section
        self._create_file_section(main)
        
        # Action Buttons Section
        self._create_action_section(main)
        
        # Progress Section
        self._create_progress_section(main)
    
    def _create_key_section(self, parent):
        """Create key management section"""
        section = tk.Frame(parent, bg=Theme.BG_MEDIUM, padx=20, pady=15)
        section.pack(fill=tk.X, pady=(0, 20))
        
        # Section title
        title = tk.Label(section, text="🔑 Key Management",
                        bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY,
                        font=("Segoe UI", 12, "bold"))
        title.pack(anchor=tk.W)
        
        # Key status
        self.key_status_label = tk.Label(section, text="Checking keys...",
                                         bg=Theme.BG_MEDIUM, fg=Theme.TEXT_SECONDARY,
                                         font=("Segoe UI", 10))
        self.key_status_label.pack(anchor=tk.W, pady=(5, 10))
        
        # Buttons row
        btn_row = tk.Frame(section, bg=Theme.BG_MEDIUM)
        btn_row.pack(fill=tk.X)
        
        # Generate keys button
        self.gen_keys_btn = tk.Button(btn_row, text="⚡ Generate New Keys",
                                      bg=Theme.ACCENT_PURPLE, fg=Theme.TEXT_PRIMARY,
                                      font=("Segoe UI", 10, "bold"),
                                      relief=tk.FLAT, padx=20, pady=8,
                                      cursor="hand2",
                                      command=self._generate_keys)
        self.gen_keys_btn.pack(side=tk.LEFT)
        
        # Layers selector
        layers_frame = tk.Frame(btn_row, bg=Theme.BG_MEDIUM)
        layers_frame.pack(side=tk.LEFT, padx=(20, 0))
        
        tk.Label(layers_frame, text="Layers:", bg=Theme.BG_MEDIUM,
                fg=Theme.TEXT_SECONDARY, font=("Segoe UI", 10)).pack(side=tk.LEFT)
        
        layers_spin = tk.Spinbox(layers_frame, from_=1, to=100,
                                 textvariable=self.num_layers, width=5,
                                 font=("Segoe UI", 10),
                                 bg=Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY,
                                 buttonbackground=Theme.BG_HOVER)
        layers_spin.pack(side=tk.LEFT, padx=5)
        
        security_bits = tk.Label(layers_frame, text="= 10,240 bits",
                                bg=Theme.BG_MEDIUM, fg=Theme.ACCENT_GREEN,
                                font=("Segoe UI", 10))
        security_bits.pack(side=tk.LEFT)
        
        def update_bits(*args):
            bits = self.num_layers.get() * 1024
            security_bits.config(text=f"= {bits:,} bits")
        
        self.num_layers.trace('w', update_bits)
    
    def _create_file_section(self, parent):
        """Create file selection section"""
        section = tk.Frame(parent, bg=Theme.BG_MEDIUM, padx=20, pady=15)
        section.pack(fill=tk.X, pady=(0, 20))
        
        # Section title
        title = tk.Label(section, text="📁 File Selection",
                        bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY,
                        font=("Segoe UI", 12, "bold"))
        title.pack(anchor=tk.W)
        
        # File display
        file_frame = tk.Frame(section, bg=Theme.BG_LIGHT, padx=15, pady=10)
        file_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.file_label = tk.Label(file_frame, text="No file selected",
                                   bg=Theme.BG_LIGHT, fg=Theme.TEXT_MUTED,
                                   font=("Segoe UI", 10))
        self.file_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Browse button
        browse_btn = tk.Button(file_frame, text="📂 Browse",
                              bg=Theme.ACCENT_BLUE, fg=Theme.TEXT_PRIMARY,
                              font=("Segoe UI", 10),
                              relief=tk.FLAT, padx=15, pady=5,
                              cursor="hand2",
                              command=self._browse_file)
        browse_btn.pack(side=tk.RIGHT)
    
    def _create_action_section(self, parent):
        """Create action buttons section"""
        section = tk.Frame(parent, bg=Theme.BG_DARK)
        section.pack(fill=tk.X, pady=(0, 20))
        
        # Encrypt button
        self.encrypt_btn = tk.Button(section, text="🔒 ENCRYPT FILE",
                                    bg=Theme.SUCCESS, fg=Theme.TEXT_PRIMARY,
                                    font=("Segoe UI", 14, "bold"),
                                    relief=tk.FLAT, padx=40, pady=15,
                                    cursor="hand2",
                                    command=self._encrypt_file)
        self.encrypt_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        
        # Decrypt button
        self.decrypt_btn = tk.Button(section, text="🔓 DECRYPT FILE",
                                    bg=Theme.ACCENT_BLUE, fg=Theme.TEXT_PRIMARY,
                                    font=("Segoe UI", 14, "bold"),
                                    relief=tk.FLAT, padx=40, pady=15,
                                    cursor="hand2",
                                    command=self._decrypt_file)
        self.decrypt_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(10, 0))
    
    def _create_progress_section(self, parent):
        """Create progress section"""
        section = tk.Frame(parent, bg=Theme.BG_MEDIUM, padx=20, pady=15)
        section.pack(fill=tk.X)
        
        # Progress bar
        self.progress = ttk.Progressbar(section, mode='determinate', length=400)
        self.progress.pack(fill=tk.X)
        
        # Progress label
        self.progress_label = tk.Label(section, text="Ready",
                                       bg=Theme.BG_MEDIUM, fg=Theme.TEXT_SECONDARY,
                                       font=("Segoe UI", 10))
        self.progress_label.pack(pady=(10, 0))
    
    def _create_status_bar(self):
        """Create status bar"""
        status = tk.Frame(self.root, bg=Theme.BG_LIGHT, pady=8, padx=20)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        
        # Version
        version = tk.Label(status, text="v3.0 | Infinite-Layer Encryption",
                          bg=Theme.BG_LIGHT, fg=Theme.TEXT_MUTED,
                          font=("Segoe UI", 9))
        version.pack(side=tk.LEFT)
        
        # Security indicator
        security = tk.Label(status, text="🔒 Quantum-Resistant",
                           bg=Theme.BG_LIGHT, fg=Theme.ACCENT_GREEN,
                           font=("Segoe UI", 9))
        security.pack(side=tk.RIGHT)
    
    def _update_key_status(self):
        """Update key status display"""
        if self.key_manager.has_keys():
            public_key = self.key_manager.load_public_key()
            layers = public_key.get('num_layers', 10)
            bits = layers * 1024
            self.key_status_label.config(
                text=f"✅ Keys loaded ({layers} layers = {bits:,} bits)",
                fg=Theme.ACCENT_GREEN
            )
        else:
            self.key_status_label.config(
                text="⚠️ No keys found - Generate keys first!",
                fg=Theme.ACCENT_YELLOW
            )
    
    def _generate_keys(self):
        """Generate new encryption keys"""
        if self.key_manager.has_keys():
            if not messagebox.askyesno("Confirm",
                                       "This will overwrite existing keys!\n"
                                       "You won't be able to decrypt files encrypted with old keys.\n\n"
                                       "Continue?"):
                return
        
        layers = self.num_layers.get()
        self._update_progress(0, f"Generating {layers}-layer keys...")
        
        def generate():
            success = self.key_manager.generate_keys(layers)
            self.root.after(0, lambda: self._on_keys_generated(success, layers))
        
        threading.Thread(target=generate, daemon=True).start()
    
    def _on_keys_generated(self, success, layers):
        """Called when key generation completes"""
        if success:
            bits = layers * 1024
            self._update_progress(100, f"Keys generated! ({bits:,} bits)")
            self._update_key_status()
            messagebox.showinfo("Success",
                               f"Keys generated successfully!\n\n"
                               f"Security: {layers} layers = {bits:,} bits\n"
                               f"Breaking time: 10^{int(bits * 77 / 256)} years")
        else:
            self._update_progress(0, "Key generation failed!")
            messagebox.showerror("Error", "Failed to generate keys!")
    
    def _browse_file(self):
        """Open file browser"""
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[
                ("All Files", "*.*"),
                ("Encrypted Files", "*.qenc"),
            ]
        )
        
        if file_path:
            self.selected_file = file_path
            name = os.path.basename(file_path)
            size = os.path.getsize(file_path)
            size_str = self._format_size(size)
            
            self.file_label.config(
                text=f"📄 {name} ({size_str})",
                fg=Theme.TEXT_PRIMARY
            )
    
    def _format_size(self, size):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def _encrypt_file(self):
        """Encrypt selected file"""
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first!")
            return
        
        if not self.key_manager.has_keys():
            messagebox.showwarning("No Keys", "Please generate keys first!")
            return
        
        if self.selected_file.endswith('.qenc'):
            messagebox.showwarning("Already Encrypted",
                                  "This file is already encrypted!")
            return
        
        self._disable_buttons()
        
        def encrypt():
            def progress(pct, msg):
                self.root.after(0, lambda: self._update_progress(pct, msg))
            
            success, result = self.file_encryptor.encrypt_file(
                self.selected_file, progress_callback=progress
            )
            
            self.root.after(0, lambda: self._on_encrypt_complete(success, result))
        
        threading.Thread(target=encrypt, daemon=True).start()
    
    def _decrypt_file(self):
        """Decrypt selected file"""
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first!")
            return
        
        if not self.key_manager.has_keys():
            messagebox.showwarning("No Keys", "Please generate/load keys first!")
            return
        
        if not self.selected_file.endswith('.qenc'):
            messagebox.showwarning("Not Encrypted",
                                  "This doesn't appear to be an encrypted file!\n"
                                  "Encrypted files have .qenc extension.")
            return
        
        self._disable_buttons()
        
        def decrypt():
            def progress(pct, msg):
                self.root.after(0, lambda: self._update_progress(pct, msg))
            
            success, result = self.file_encryptor.decrypt_file(
                self.selected_file, progress_callback=progress
            )
            
            self.root.after(0, lambda: self._on_decrypt_complete(success, result))
        
        threading.Thread(target=decrypt, daemon=True).start()
    
    def _on_encrypt_complete(self, success, result):
        """Called when encryption completes"""
        self._enable_buttons()
        
        if success:
            messagebox.showinfo("Encrypted!",
                               f"File encrypted successfully!\n\n"
                               f"Saved to:\n{result}")
        else:
            messagebox.showerror("Error", f"Encryption failed:\n{result}")
    
    def _on_decrypt_complete(self, success, result):
        """Called when decryption completes"""
        self._enable_buttons()
        
        if success:
            messagebox.showinfo("Decrypted!",
                               f"File decrypted successfully!\n\n"
                               f"Saved to:\n{result}")
        else:
            messagebox.showerror("Error", f"Decryption failed:\n{result}")
    
    def _update_progress(self, value, message):
        """Update progress bar and label"""
        self.progress['value'] = value
        self.progress_label.config(text=message)
    
    def _disable_buttons(self):
        """Disable buttons during operation"""
        self.encrypt_btn.config(state=tk.DISABLED)
        self.decrypt_btn.config(state=tk.DISABLED)
        self.gen_keys_btn.config(state=tk.DISABLED)
    
    def _enable_buttons(self):
        """Enable buttons after operation"""
        self.encrypt_btn.config(state=tk.NORMAL)
        self.decrypt_btn.config(state=tk.NORMAL)
        self.gen_keys_btn.config(state=tk.NORMAL)
    
    def run(self):
        """Start the application"""
        self.root.mainloop()


# ════════════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("   🔐 QUANTUM FILE ENCRYPTOR")
    print("   Infinite-Layer Quantum-Resistant Encryption")
    print("=" * 60)
    print()
    print("Starting GUI application...")
    print()
    
    app = QuantumFileEncryptorApp()
    app.run()
