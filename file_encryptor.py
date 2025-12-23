"""
╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                  ║
║   🔐 QUANTUM FILE ENCRYPTOR - GUI Application (QUANTUM VAULT EDITION)                           ║
║                                                                                                  ║
║   A powerful file encryption tool using Post-Quantum Hybrid Encryption                          ║
║                                                                                                  ║
║   Security Features:                                                                             ║
║   • ML-KEM-1024 post-quantum key encapsulation (FIPS 203 - August 2024)                         ║
║   • AES-256-GCM authenticated encryption (AEAD)                                                 ║
║   • Argon2id memory-hard key derivation                                                         ║
║   • Hybrid encryption: Classical + Post-Quantum                                                 ║
║   • NIST Level 5 security (maximum quantum resistance)                                          ║
║   • "Harvest Now, Decrypt Later" attack protection                                              ║
║                                                                                                  ║
║   Security: 256-bit classical + Quantum-Resistant                                               ║
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
        print("Make sure secure_vault_quantum.py or secure_vault.py exists.")
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
# FILE ENCRYPTOR ENGINE
# ════════════════════════════════════════════════════════════════════════════════════════

class FileEncryptor:
    """Handles file encryption/decryption using QuantumSecureVault"""
    
    MAGIC_HEADER = b"QVLT"  # Quantum VauLT
    VERSION = 2
    
    def __init__(self):
        if QUANTUM_AVAILABLE:
            self.vault = QuantumSecureVault()
        else:
            self.vault = SecureVault()
    
    def generate_password(self) -> str:
        """Generate a secure random password/key"""
        # Generate 32 bytes of random data and encode as base64
        return base64.b64encode(secrets.token_bytes(32)).decode('ascii')
    
    def encrypt_file(self, input_path: str, password: str, output_path: str = None, 
                     progress_callback=None) -> tuple:
        """Encrypt a file with password"""
        try:
            input_path = Path(input_path)
            if output_path is None:
                output_path = input_path.with_suffix(input_path.suffix + ".qenc")
            else:
                output_path = Path(output_path)
            
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
                'encryption_level': ENCRYPTION_LEVEL,
            }
            metadata_bytes = json.dumps(metadata).encode()
            
            # Combine metadata length + metadata + plaintext
            combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
            
            if progress_callback:
                progress_callback(20, "Encrypting with quantum-resistant algorithm...")
            
            # Encrypt using QuantumSecureVault
            encrypted_data = self.vault.encrypt(combined, password)
            
            if progress_callback:
                progress_callback(80, "Writing encrypted file...")
            
            # Write encrypted file with header
            with open(output_path, 'wb') as f:
                # Write header
                f.write(self.MAGIC_HEADER)
                f.write(self.VERSION.to_bytes(2, 'big'))
                # Write encrypted data length and data
                f.write(len(encrypted_data).to_bytes(8, 'big'))
                f.write(encrypted_data)
            
            if progress_callback:
                progress_callback(100, "Encryption complete!")
            
            return True, str(output_path)
            
        except Exception as e:
            return False, str(e)
    
    def decrypt_file(self, input_path: str, password: str, output_path: str = None,
                     progress_callback=None) -> tuple:
        """Decrypt a file with password"""
        try:
            input_path = Path(input_path)
            
            if progress_callback:
                progress_callback(0, "Reading encrypted file...")
            
            with open(input_path, 'rb') as f:
                # Read and verify header
                magic = f.read(4)
                if magic != self.MAGIC_HEADER:
                    raise ValueError("Not a valid QVLT encrypted file!")
                
                version = int.from_bytes(f.read(2), 'big')
                
                # Read encrypted data
                enc_len = int.from_bytes(f.read(8), 'big')
                encrypted_data = f.read(enc_len)
            
            if progress_callback:
                progress_callback(20, "Decrypting with quantum-resistant algorithm...")
            
            # Decrypt using QuantumSecureVault
            try:
                decrypted = self.vault.decrypt(encrypted_data, password)
            except ValueError:
                return False, "Wrong password! The password you entered is incorrect."
            
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
        self.root.geometry("800x650")
        self.root.configure(bg=Theme.BG_DARK)
        self.root.minsize(700, 550)
        
        # Initialize components
        self.file_encryptor = FileEncryptor()
        
        # Selected file
        self.selected_file = None
        self.current_password = tk.StringVar()
        
        # Build UI
        self._create_styles()
        self._create_header()
        self._create_main_content()
        self._create_status_bar()
    
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
        if QUANTUM_AVAILABLE:
            subtitle_text = "Post-Quantum Hybrid Encryption (ML-KEM-1024 + AES-256-GCM)"
        else:
            subtitle_text = "Industry-Standard Encryption (AES-256-GCM + Argon2id)"
        
        subtitle = tk.Label(header, text=subtitle_text,
                           bg=Theme.BG_DARK, fg=Theme.TEXT_SECONDARY,
                           font=("Segoe UI", 11))
        subtitle.pack()
        
        # Security badge
        if QUANTUM_AVAILABLE:
            badge_text = "🛡️ NIST Level 5 | Quantum-Resistant | FIPS 203"
        else:
            badge_text = "🛡️ 256-bit Security | AES-256-GCM"
        
        security = tk.Label(header, text=badge_text,
                           bg=Theme.BG_DARK, fg=Theme.ACCENT_GREEN,
                           font=("Segoe UI", 10))
        security.pack(pady=(10, 0))
    
    def _create_main_content(self):
        """Create main content area"""
        main = tk.Frame(self.root, bg=Theme.BG_DARK, padx=40)
        main.pack(fill=tk.BOTH, expand=True)
        
        # File Selection Section
        self._create_file_section(main)
        
        # Password Section
        self._create_password_section(main)
        
        # Action Buttons Section
        self._create_action_section(main)
        
        # Progress Section
        self._create_progress_section(main)
    
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
    
    def _create_password_section(self, parent):
        """Create password entry section"""
        section = tk.Frame(parent, bg=Theme.BG_MEDIUM, padx=20, pady=15)
        section.pack(fill=tk.X, pady=(0, 20))
        
        # Section title
        title = tk.Label(section, text="🔑 Encryption Key / Password",
                        bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY,
                        font=("Segoe UI", 12, "bold"))
        title.pack(anchor=tk.W)
        
        # Password entry frame
        pwd_frame = tk.Frame(section, bg=Theme.BG_LIGHT, padx=15, pady=10)
        pwd_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.password_entry = tk.Entry(pwd_frame, textvariable=self.current_password,
                                       bg=Theme.BG_HOVER, fg=Theme.TEXT_PRIMARY,
                                       font=("Consolas", 11), show="*",
                                       insertbackground=Theme.TEXT_PRIMARY)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        # Toggle show/hide
        self.show_password = tk.BooleanVar(value=False)
        show_btn = tk.Checkbutton(pwd_frame, text="👁", 
                                 variable=self.show_password,
                                 command=self._toggle_password,
                                 bg=Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY,
                                 selectcolor=Theme.BG_HOVER,
                                 activebackground=Theme.BG_LIGHT,
                                 font=("Segoe UI", 12))
        show_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Generate key button
        gen_btn = tk.Button(pwd_frame, text="⚡ Generate",
                           bg=Theme.ACCENT_PURPLE, fg=Theme.TEXT_PRIMARY,
                           font=("Segoe UI", 10),
                           relief=tk.FLAT, padx=15, pady=5,
                           cursor="hand2",
                           command=self._generate_password)
        gen_btn.pack(side=tk.RIGHT)
        
        # Info text
        info = tk.Label(section, 
                       text="💡 For encryption: Generate a new key and save it. For decryption: Enter the key you used.",
                       bg=Theme.BG_MEDIUM, fg=Theme.TEXT_MUTED,
                       font=("Segoe UI", 9))
        info.pack(anchor=tk.W, pady=(10, 0))
    
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
        version = tk.Label(status, text="v2.0 | Post-Quantum Hybrid Encryption",
                          bg=Theme.BG_LIGHT, fg=Theme.TEXT_MUTED,
                          font=("Segoe UI", 9))
        version.pack(side=tk.LEFT)
        
        # Security indicator
        if QUANTUM_AVAILABLE:
            sec_text = "🔒 Quantum-Resistant"
        else:
            sec_text = "🔒 AES-256-GCM"
        
        security = tk.Label(status, text=sec_text,
                           bg=Theme.BG_LIGHT, fg=Theme.ACCENT_GREEN,
                           font=("Segoe UI", 9))
        security.pack(side=tk.RIGHT)
    
    def _toggle_password(self):
        """Toggle password visibility"""
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def _generate_password(self):
        """Generate a secure password"""
        password = self.file_encryptor.generate_password()
        self.current_password.set(password)
        self.password_entry.config(show="")  # Show the generated password
        self.show_password.set(True)
        messagebox.showinfo("Key Generated", 
                           "A secure encryption key has been generated!\n\n"
                           "⚠️ IMPORTANT: Copy and save this key somewhere safe.\n"
                           "You will need it to decrypt your files.")
    
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
        
        password = self.current_password.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password or generate a key first!")
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
                self.selected_file, password, progress_callback=progress
            )
            
            self.root.after(0, lambda: self._on_encrypt_complete(success, result))
        
        threading.Thread(target=encrypt, daemon=True).start()
    
    def _decrypt_file(self):
        """Decrypt selected file"""
        if not self.selected_file:
            messagebox.showwarning("No File", "Please select a file first!")
            return
        
        password = self.current_password.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter the decryption password/key!")
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
                self.selected_file, password, progress_callback=progress
            )
            
            self.root.after(0, lambda: self._on_decrypt_complete(success, result))
        
        threading.Thread(target=decrypt, daemon=True).start()
    
    def _on_encrypt_complete(self, success, result):
        """Called when encryption completes"""
        self._enable_buttons()
        
        if success:
            messagebox.showinfo("Encrypted!",
                               f"File encrypted successfully!\n\n"
                               f"Saved to:\n{result}\n\n"
                               f"⚠️ Remember to save your encryption key!")
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
    
    def _enable_buttons(self):
        """Enable buttons after operation"""
        self.encrypt_btn.config(state=tk.NORMAL)
        self.decrypt_btn.config(state=tk.NORMAL)
    
    def run(self):
        """Start the application"""
        self.root.mainloop()


# ════════════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("   🔐 QUANTUM FILE ENCRYPTOR")
    if QUANTUM_AVAILABLE:
        print("   Post-Quantum Hybrid Encryption (ML-KEM-1024)")
    else:
        print("   Industry-Standard Encryption (AES-256-GCM)")
    print("=" * 60)
    print()
    print("Starting GUI application...")
    print()
    
    app = QuantumFileEncryptorApp()
    app.run()
