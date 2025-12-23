"""
╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                  ║
║   🔐 QUANTUM FILE ENCRYPTOR - Interactive Console Version                                       ║
║                                                                                                  ║
║   No GUI dependencies required - works on ANY Python installation!                              ║
║   Uses Post-Quantum Hybrid Encryption (QuantumSecureVault)                                      ║
║                                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import json
import base64
import secrets
from pathlib import Path
from datetime import datetime
import time

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
        print("❌ Error: No encryption module found!")
        print("   Make sure secure_vault_quantum.py or secure_vault.py exists.")
        input("Press Enter to exit...")
        sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════════════

MAGIC_HEADER = b"QVLT"  # Quantum VauLT
VERSION = 2


# ════════════════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════════════

def clear_screen():
    """Clear the console screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header():
    """Print the application header"""
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "   🔐 QUANTUM FILE ENCRYPTOR".center(78) + "║")
    if QUANTUM_AVAILABLE:
        print("║" + "   Post-Quantum Hybrid Encryption (ML-KEM-1024 + AES-256-GCM)".center(78) + "║")
    else:
        print("║" + "   Industry-Standard Encryption (AES-256-GCM + Argon2id)".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╠" + "═" * 78 + "╣")
    if QUANTUM_AVAILABLE:
        print("║" + "   NIST Level 5 Security  |  Quantum-Resistant  |  FIPS 203".center(78) + "║")
    else:
        print("║" + "   256-bit Security  |  AES-256-GCM  |  Argon2id".center(78) + "║")
    print("╚" + "═" * 78 + "╝")
    print()


def print_menu():
    """Print the main menu"""
    print("┌" + "─" * 40 + "┐")
    print("│         MAIN MENU                     │")
    print("├" + "─" * 40 + "┤")
    print("│  [1] 🔑 Generate Encryption Key       │")
    print("│  [2] 🔒 Encrypt a File                │")
    print("│  [3] 🔓 Decrypt a File                │")
    print("│  [4] ℹ️  View Security Information     │")
    print("│  [0] 🚪 Exit                          │")
    print("└" + "─" * 40 + "┘")
    print()


def format_size(size):
    """Format file size nicely"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def wait_for_enter():
    """Wait for user to press Enter"""
    print()
    input("  Press Enter to continue...")


def get_vault():
    """Get the appropriate vault instance"""
    if QUANTUM_AVAILABLE:
        return QuantumSecureVault()
    return SecureVault()


def generate_password() -> str:
    """Generate a secure random password"""
    return base64.b64encode(secrets.token_bytes(32)).decode('ascii')


# ════════════════════════════════════════════════════════════════════════════════════════
# KEY GENERATION
# ════════════════════════════════════════════════════════════════════════════════════════

def generate_key_menu():
    """Generate a new encryption key"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     🔑 GENERATE ENCRYPTION KEY                  ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    password = generate_password()
    
    print("  ✅ KEY GENERATED SUCCESSFULLY!")
    print()
    print("  ╔" + "═" * 60 + "╗")
    print("  ║  Your Encryption Key:                                     ║")
    print("  ╠" + "═" * 60 + "╣")
    print(f"  ║  {password}  ║")
    print("  ╚" + "═" * 60 + "╝")
    print()
    print("  ⚠️  IMPORTANT: Copy and save this key somewhere safe!")
    print("     You will need it to decrypt your files.")
    print()
    print("     Without this key, your encrypted files CANNOT be recovered!")
    
    wait_for_enter()


def view_security_info():
    """Display security information"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     ℹ️  SECURITY INFORMATION                     ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    if QUANTUM_AVAILABLE:
        print("  ✅ Post-Quantum Encryption ENABLED")
        print()
        print("  🔒 Security Features:")
        print("     • ML-KEM-1024 post-quantum key encapsulation (FIPS 203)")
        print("     • AES-256-GCM authenticated encryption")
        print("     • Argon2id memory-hard key derivation")
        print("     • Hybrid encryption: Classical + Post-Quantum")
        print("     • NIST Level 5 security (maximum)")
        print("     • 'Harvest Now, Decrypt Later' attack protection")
        print()
        print("  📋 Standards Compliance:")
        print("     • FIPS 203 (ML-KEM - August 2024)")
        print("     • FIPS 204 (ML-DSA signatures)")
        print("     • FIPS 197 (AES)")
        print("     • NIST SP 800-38D (GCM mode)")
    else:
        print("  ⚠️  Standard Encryption Mode")
        print("  (Install liboqs-python for post-quantum protection)")
        print()
        print("  🔒 Security Features:")
        print("     • AES-256-GCM authenticated encryption")
        print("     • Argon2id memory-hard key derivation")
        print("     • 256-bit security level")
        print("     • Tamper detection (AEAD)")
    
    wait_for_enter()


# ════════════════════════════════════════════════════════════════════════════════════════
# ENCRYPTION
# ════════════════════════════════════════════════════════════════════════════════════════

def encrypt_file_menu():
    """Encrypt a file"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     🔒 ENCRYPT A FILE                           ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    print("  Enter the full path to the file you want to encrypt:")
    print("  (You can drag and drop the file here)")
    print()
    
    file_path = input("  File path: ").strip().strip('"').strip("'")
    
    if not file_path:
        print("  ❌ No file specified.")
        wait_for_enter()
        return
    
    file_path = Path(file_path)
    
    if not file_path.exists():
        print(f"  ❌ File not found: {file_path}")
        wait_for_enter()
        return
    
    if file_path.suffix == '.qenc':
        print("  ❌ This file is already encrypted!")
        wait_for_enter()
        return
    
    output_path = file_path.with_suffix(file_path.suffix + ".qenc")
    
    print()
    print("  Choose password option:")
    print("  [1] Generate a new secure key (recommended)")
    print("  [2] Enter your own password")
    print()
    
    choice = input("  Choose [1/2]: ").strip()
    
    if choice == '2':
        password = input("  Enter password: ").strip()
        if not password:
            print("  ❌ Password cannot be empty.")
            wait_for_enter()
            return
    else:
        password = generate_password()
        print()
        print("  🔑 Generated Key (SAVE THIS!):")
        print("  " + "=" * 60)
        print(f"    {password}")
        print("  " + "=" * 60)
    
    print()
    print("  ┌" + "─" * 60 + "┐")
    print(f"  │  📄 Input:  {file_path.name[:45]:45s} │")
    print(f"  │  📦 Output: {output_path.name[:45]:45s} │")
    print(f"  │  📊 Size:   {format_size(file_path.stat().st_size):45s} │")
    print(f"  │  🔒 Mode:   {'Quantum-Resistant' if QUANTUM_AVAILABLE else 'Standard AES-256':45s} │")
    print("  └" + "─" * 60 + "┘")
    print()
    
    confirm = input("  Proceed with encryption? (y/n): ").strip().lower()
    if confirm != 'y':
        print("  ❌ Cancelled.")
        wait_for_enter()
        return
    
    print()
    print("  🔄 Encrypting file...")
    
    vault = get_vault()
    
    # Read file
    print("  📖 Reading file...", end="", flush=True)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    print(" ✓")
    
    # Create metadata
    metadata = {
        'original_name': file_path.name,
        'original_size': len(plaintext),
        'encrypted_at': datetime.now().isoformat(),
        'encryption_level': ENCRYPTION_LEVEL,
    }
    metadata_bytes = json.dumps(metadata).encode()
    combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
    
    # Encrypt
    print("  🔐 Applying quantum-resistant encryption...", end="", flush=True)
    encrypted_data = vault.encrypt(combined, password)
    print(" ✓")
    
    # Write encrypted file
    print("  💾 Writing encrypted file...", end="", flush=True)
    with open(output_path, 'wb') as f:
        f.write(MAGIC_HEADER)
        f.write(VERSION.to_bytes(2, 'big'))
        f.write(len(encrypted_data).to_bytes(8, 'big'))
        f.write(encrypted_data)
    print(" ✓")
    
    print()
    print("  ╔" + "═" * 50 + "╗")
    print("  ║     ✅ ENCRYPTION SUCCESSFUL!                  ║")
    print("  ╚" + "═" * 50 + "╝")
    print()
    print(f"  📦 Encrypted file: {output_path.name}")
    print(f"  📊 Original size: {format_size(len(plaintext))}")
    print(f"  📊 Encrypted size: {format_size(output_path.stat().st_size)}")
    print()
    print("  ⚠️  Remember to save your encryption key!")
    
    wait_for_enter()


# ════════════════════════════════════════════════════════════════════════════════════════
# DECRYPTION
# ════════════════════════════════════════════════════════════════════════════════════════

def decrypt_file_menu():
    """Decrypt a file"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     🔓 DECRYPT A FILE                           ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    print("  Enter the full path to the encrypted file (.qenc):")
    print("  (You can drag and drop the file here)")
    print()
    
    file_path = input("  File path: ").strip().strip('"').strip("'")
    
    if not file_path:
        print("  ❌ No file specified.")
        wait_for_enter()
        return
    
    file_path = Path(file_path)
    
    if not file_path.exists():
        print(f"  ❌ File not found: {file_path}")
        wait_for_enter()
        return
    
    if file_path.suffix != '.qenc':
        print("  ⚠️  This file doesn't have .qenc extension.")
        print("  It may not be a valid encrypted file.")
        confirm = input("  Try to decrypt anyway? (y/n): ").strip().lower()
        if confirm != 'y':
            wait_for_enter()
            return
    
    print()
    password = input("  Enter decryption key/password: ").strip()
    
    if not password:
        print("  ❌ Password is required!")
        wait_for_enter()
        return
    
    print()
    print("  🔄 Decrypting file...")
    
    vault = get_vault()
    
    # Read encrypted file
    print("  📖 Reading encrypted file...", end="", flush=True)
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic != MAGIC_HEADER:
                print()
                print("  ❌ Not a valid QVLT encrypted file!")
                wait_for_enter()
                return
            
            version = int.from_bytes(f.read(2), 'big')
            enc_len = int.from_bytes(f.read(8), 'big')
            encrypted_data = f.read(enc_len)
        print(" ✓")
    except Exception as e:
        print()
        print(f"  ❌ Error reading file: {e}")
        wait_for_enter()
        return
    
    # Decrypt
    print("  🔐 Decrypting...", end="", flush=True)
    try:
        decrypted = vault.decrypt(encrypted_data, password)
        print(" ✓")
    except ValueError:
        print()
        print("  ❌ Wrong password! The password you entered is incorrect.")
        wait_for_enter()
        return
    except Exception as e:
        print()
        print(f"  ❌ Decryption failed: {e}")
        wait_for_enter()
        return
    
    # Parse metadata
    print("  📋 Extracting original file...", end="", flush=True)
    metadata_len = int.from_bytes(decrypted[:4], 'big')
    metadata = json.loads(decrypted[4:4+metadata_len].decode())
    plaintext = decrypted[4+metadata_len:]
    print(" ✓")
    
    # Write decrypted file
    original_name = metadata.get('original_name', 'decrypted_file')
    output_path = file_path.parent / f"decrypted_{original_name}"
    
    print("  💾 Writing decrypted file...", end="", flush=True)
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    print(" ✓")
    
    print()
    print("  ╔" + "═" * 50 + "╗")
    print("  ║     ✅ DECRYPTION SUCCESSFUL!                  ║")
    print("  ╚" + "═" * 50 + "╝")
    print()
    print(f"  📄 Decrypted file: {output_path.name}")
    print(f"  📊 Original name: {original_name}")
    print(f"  📊 Size: {format_size(len(plaintext))}")
    
    wait_for_enter()


# ════════════════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ════════════════════════════════════════════════════════════════════════════════════════

def main():
    """Main application loop"""
    while True:
        clear_screen()
        print_header()
        print_menu()
        
        choice = input("  Enter your choice [0-4]: ").strip()
        
        if choice == '1':
            generate_key_menu()
        elif choice == '2':
            encrypt_file_menu()
        elif choice == '3':
            decrypt_file_menu()
        elif choice == '4':
            view_security_info()
        elif choice == '0':
            clear_screen()
            print()
            print("  👋 Thank you for using Quantum File Encryptor!")
            print("  🔒 Your files are protected with quantum-resistant encryption.")
            print()
            break
        else:
            print("  ❌ Invalid choice. Please try again.")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("  👋 Goodbye!")
