"""
╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                  ║
║   🔐 QUANTUM FILE ENCRYPTOR - Interactive Console Version                                       ║
║                                                                                                  ║
║   No GUI dependencies required - works on ANY Python installation!                              ║
║                                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import json
import base64
from pathlib import Path
from datetime import datetime
import time

# Add parent directory to import the encryption module
sys.path.insert(0, str(Path(__file__).parent.parent / "QUANTUM_RESISTANT_ENCRYPTION"))

try:
    from quantum_encryption_infinite import InfiniteQuantumEncryption
except ImportError:
    print("❌ Error: quantum_encryption_infinite.py not found!")
    print("   Make sure QUANTUM_RESISTANT_ENCRYPTION folder exists.")
    input("Press Enter to exit...")
    sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════════════

KEYS_DIR = Path(__file__).parent / "keys"
MAGIC_HEADER = b"QENC"
VERSION = 1


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
    print("║" + "   Infinite-Layer Quantum-Resistant Encryption".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╠" + "═" * 78 + "╣")
    print("║" + "   Security: 10,240+ bits  |  Breaking Time: 10^3,082+ years".center(78) + "║")
    print("╚" + "═" * 78 + "╝")
    print()


def print_menu():
    """Print the main menu"""
    print("┌" + "─" * 40 + "┐")
    print("│         MAIN MENU                     │")
    print("├" + "─" * 40 + "┤")
    print("│  [1] 🔑 Generate New Keys             │")
    print("│  [2] 🔒 Encrypt a File                │")
    print("│  [3] 🔓 Decrypt a File                │")
    print("│  [4] ℹ️  View Key Information          │")
    print("│  [5] 📂 Open Keys Folder              │")
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


def progress_bar(current, total, width=40):
    """Display a progress bar"""
    percent = current / total
    filled = int(width * percent)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r  [{bar}] {percent*100:.0f}%", end="", flush=True)


def wait_for_enter():
    """Wait for user to press Enter"""
    print()
    input("  Press Enter to continue...")


# ════════════════════════════════════════════════════════════════════════════════════════
# KEY MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════════════════

def has_keys():
    """Check if keys exist"""
    return (KEYS_DIR / "public_key.json").exists() and (KEYS_DIR / "private_key.json").exists()


def generate_keys():
    """Generate new encryption keys"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     🔑 GENERATE NEW KEYS                        ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    if has_keys():
        print("  ⚠️  WARNING: Keys already exist!")
        print("  Generating new keys will make OLD encrypted files unreadable!")
        print()
        confirm = input("  Type 'YES' to confirm: ")
        if confirm != "YES":
            print("  ❌ Cancelled.")
            wait_for_enter()
            return
        print()
    
    # Get number of layers
    print("  How many encryption layers? (more = more secure)")
    print("  • 10 layers = 10,240 bits (recommended)")
    print("  • 50 layers = 51,200 bits (ultra)")
    print("  • 100 layers = 102,400 bits (insane)")
    print()
    
    try:
        layers = int(input("  Enter number of layers [10]: ").strip() or "10")
        if layers < 1:
            layers = 10
    except ValueError:
        layers = 10
    
    print()
    print(f"  🔄 Generating {layers}-layer encryption keys...")
    print(f"     Security: {layers * 1024:,} bits")
    print()
    
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    
    crypto = InfiniteQuantumEncryption(num_layers=layers)
    public_key, private_key = crypto.generate_keypair()
    
    # Save public key
    public_data = {
        'encryption_pk': base64.b64encode(public_key['encryption_pk']).decode(),
        'signing_pk': base64.b64encode(public_key['signing_pk']).decode(),
        'num_layers': public_key['num_layers'],
        'version': public_key['version'],
        'created': datetime.now().isoformat(),
    }
    
    with open(KEYS_DIR / "public_key.json", 'w') as f:
        json.dump(public_data, f, indent=2)
    
    # Save private key
    private_data = {
        'encryption_sk': base64.b64encode(private_key['encryption_sk']).decode(),
        'signing_sk': base64.b64decode(private_key['signing_sk']).decode() if isinstance(private_key['signing_sk'], bytes) else private_key['signing_sk'],
        'num_layers': private_key['num_layers'],
        'version': private_key['version'],
        'created': datetime.now().isoformat(),
    }
    
    # Fix: Ensure bytes are properly encoded
    private_data = {
        'encryption_sk': base64.b64encode(private_key['encryption_sk']).decode(),
        'signing_sk': base64.b64encode(private_key['signing_sk']).decode(),
        'num_layers': private_key['num_layers'],
        'version': private_key['version'],
        'created': datetime.now().isoformat(),
    }
    
    with open(KEYS_DIR / "private_key.json", 'w') as f:
        json.dump(private_data, f, indent=2)
    
    print("  ✅ KEYS GENERATED SUCCESSFULLY!")
    print()
    print(f"  📂 Location: {KEYS_DIR}")
    print(f"  🔒 Security: {layers} layers = {layers * 1024:,} bits")
    print(f"  ⏱️  Breaking time: 10^{int(layers * 1024 * 77 / 256)} years")
    print()
    print("  ⚠️  IMPORTANT: Keep your private_key.json SECURE!")
    print("     Anyone with this file can decrypt your files!")
    
    wait_for_enter()


def load_public_key():
    """Load public key"""
    try:
        with open(KEYS_DIR / "public_key.json", 'r') as f:
            data = json.load(f)
        return {
            'encryption_pk': base64.b64decode(data['encryption_pk']),
            'signing_pk': base64.b64decode(data['signing_pk']),
            'num_layers': data['num_layers'],
            'version': data['version'],
        }
    except FileNotFoundError:
        return None


def load_private_key():
    """Load private key"""
    try:
        with open(KEYS_DIR / "private_key.json", 'r') as f:
            data = json.load(f)
        return {
            'encryption_sk': base64.b64decode(data['encryption_sk']),
            'signing_sk': base64.b64decode(data['signing_sk']),
            'num_layers': data['num_layers'],
            'version': data['version'],
        }
    except FileNotFoundError:
        return None


def view_key_info():
    """Display key information"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     ℹ️  KEY INFORMATION                          ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    if not has_keys():
        print("  ❌ No keys found!")
        print("  👉 Use option [1] to generate keys first.")
        wait_for_enter()
        return
    
    public_key = load_public_key()
    
    layers = public_key['num_layers']
    bits = layers * 1024
    breaking_exp = int(bits * 77 / 256)
    
    print("  ✅ Keys Found")
    print()
    print("  ┌" + "─" * 45 + "┐")
    print(f"  │  📂 Location: {str(KEYS_DIR)[:30]:30s} │")
    print(f"  │  🔢 Layers: {layers:<33} │")
    print(f"  │  🔒 Security: {bits:,} bits{' ' * (26 - len(f'{bits:,}'))} │")
    print(f"  │  ⏱️  Breaking: 10^{breaking_exp} years{' ' * (22 - len(str(breaking_exp)))} │")
    print(f"  │  📋 Version: {public_key['version']:<31} │")
    print("  └" + "─" * 45 + "┘")
    
    wait_for_enter()


def open_keys_folder():
    """Open the keys folder in file explorer"""
    if os.name == 'nt':  # Windows
        os.startfile(str(KEYS_DIR))
    elif os.name == 'posix':  # macOS/Linux
        os.system(f'open "{KEYS_DIR}"' if sys.platform == 'darwin' else f'xdg-open "{KEYS_DIR}"')
    print("  📂 Opening keys folder...")
    time.sleep(1)


# ════════════════════════════════════════════════════════════════════════════════════════
# ENCRYPTION
# ════════════════════════════════════════════════════════════════════════════════════════

def encrypt_file():
    """Encrypt a file"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     🔒 ENCRYPT A FILE                           ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    if not has_keys():
        print("  ❌ No keys found!")
        print("  👉 Use option [1] to generate keys first.")
        wait_for_enter()
        return
    
    public_key = load_public_key()
    
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
    print("  ┌" + "─" * 60 + "┐")
    print(f"  │  📄 Input:  {file_path.name[:45]:45s} │")
    print(f"  │  📦 Output: {output_path.name[:45]:45s} │")
    print(f"  │  📊 Size:   {format_size(file_path.stat().st_size):45s} │")
    print(f"  │  🔢 Layers: {public_key['num_layers']:<45} │")
    print("  └" + "─" * 60 + "┘")
    print()
    
    confirm = input("  Proceed with encryption? (y/n): ").strip().lower()
    if confirm != 'y':
        print("  ❌ Cancelled.")
        wait_for_enter()
        return
    
    print()
    print("  🔄 Encrypting file...")
    
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
    }
    metadata_bytes = json.dumps(metadata).encode()
    combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
    
    # Encrypt
    print("  🔐 Applying quantum-resistant encryption...", end="", flush=True)
    crypto = InfiniteQuantumEncryption(num_layers=public_key['num_layers'])
    encrypted = crypto.encrypt(combined, public_key)
    print(" ✓")
    
    # Write encrypted file
    print("  💾 Writing encrypted file...", end="", flush=True)
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
    print("  🔒 Your file is now protected with quantum-resistant encryption!")
    
    wait_for_enter()


# ════════════════════════════════════════════════════════════════════════════════════════
# DECRYPTION
# ════════════════════════════════════════════════════════════════════════════════════════

def decrypt_file():
    """Decrypt a file"""
    clear_screen()
    print_header()
    
    print("╔" + "═" * 50 + "╗")
    print("║     🔓 DECRYPT A FILE                           ║")
    print("╚" + "═" * 50 + "╝")
    print()
    
    if not has_keys():
        print("  ❌ No keys found!")
        print("  👉 You need the private key that was used to encrypt the file.")
        wait_for_enter()
        return
    
    private_key = load_private_key()
    
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
    print("  🔄 Decrypting file...")
    
    # Read encrypted file
    print("  📖 Reading encrypted file...", end="", flush=True)
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic != MAGIC_HEADER:
                print()
                print("  ❌ Not a valid QENC encrypted file!")
                wait_for_enter()
                return
            
            version = int.from_bytes(f.read(2), 'big')
            num_layers = int.from_bytes(f.read(4), 'big')
            
            ephemeral_len = int.from_bytes(f.read(4), 'big')
            ephemeral_key = f.read(ephemeral_len)
            
            enc_len = int.from_bytes(f.read(8), 'big')
            encrypted_data = f.read(enc_len)
        print(" ✓")
    except Exception as e:
        print()
        print(f"  ❌ Error reading file: {e}")
        wait_for_enter()
        return
    
    encrypted = {
        'ephemeral_key': ephemeral_key,
        'encrypted_data': encrypted_data,
        'num_layers': num_layers,
        'version': "3.0.0-INFINITE",
    }
    
    # Decrypt
    print(f"  🔐 Decrypting {num_layers} layers...", end="", flush=True)
    try:
        crypto = InfiniteQuantumEncryption(num_layers=num_layers)
        decrypted = crypto.decrypt(encrypted, private_key)
        print(" ✓")
    except Exception as e:
        print()
        print(f"  ❌ Decryption failed: {e}")
        print("  This may mean the file was encrypted with different keys.")
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
        
        # Show key status
        if has_keys():
            pk = load_public_key()
            print(f"  🔑 Keys: ✅ Loaded ({pk['num_layers']} layers = {pk['num_layers'] * 1024:,} bits)")
        else:
            print("  🔑 Keys: ⚠️  Not found - Generate keys first!")
        print()
        
        print_menu()
        
        choice = input("  Enter your choice [0-5]: ").strip()
        
        if choice == '1':
            generate_keys()
        elif choice == '2':
            encrypt_file()
        elif choice == '3':
            decrypt_file()
        elif choice == '4':
            view_key_info()
        elif choice == '5':
            KEYS_DIR.mkdir(parents=True, exist_ok=True)
            open_keys_folder()
        elif choice == '0':
            clear_screen()
            print()
            print("  👋 Thank you for using Quantum File Encryptor!")
            print("  🔒 Your files are protected with infinite-layer encryption.")
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
