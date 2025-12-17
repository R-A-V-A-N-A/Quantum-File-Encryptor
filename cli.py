"""
🔐 QUANTUM FILE ENCRYPTOR - Command Line Interface

Usage:
    python cli.py keygen [--layers N]     Generate encryption keys
    python cli.py encrypt <file>          Encrypt a file
    python cli.py decrypt <file.qenc>     Decrypt a file
    python cli.py info                    Show key information
"""

import sys
import os
import json
import base64
import argparse
from pathlib import Path
from datetime import datetime

# Add parent directory to import the encryption module
sys.path.insert(0, str(Path(__file__).parent.parent / "QUANTUM_RESISTANT_ENCRYPTION"))

try:
    from quantum_encryption_infinite import InfiniteQuantumEncryption
except ImportError:
    print("❌ Error: quantum_encryption_infinite.py not found!")
    print("   Make sure QUANTUM_RESISTANT_ENCRYPTION folder exists.")
    sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════════════

KEYS_DIR = Path(__file__).parent / "keys"
MAGIC_HEADER = b"QENC"
VERSION = 1


# ════════════════════════════════════════════════════════════════════════════════════════
# KEY MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════════════════

def generate_keys(layers: int = 10):
    """Generate new encryption keys"""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"🔑 Generating {layers}-layer encryption keys...")
    print(f"   Security: {layers * 1024:,} bits")
    print()
    
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
        'signing_sk': base64.b64encode(private_key['signing_sk']).decode(),
        'num_layers': private_key['num_layers'],
        'version': private_key['version'],
        'created': datetime.now().isoformat(),
    }
    
    with open(KEYS_DIR / "private_key.json", 'w') as f:
        json.dump(private_data, f, indent=2)
    
    print("✅ Keys generated successfully!")
    print(f"   📂 Saved to: {KEYS_DIR}")
    print()
    print("⚠️  IMPORTANT: Keep your private_key.json secure!")
    print("   Anyone with this file can decrypt your files.")


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


def show_info():
    """Show key information"""
    print("=" * 60)
    print("   🔐 QUANTUM FILE ENCRYPTOR - Key Information")
    print("=" * 60)
    print()
    
    public_key = load_public_key()
    if public_key is None:
        print("❌ No keys found!")
        print("   Run: python cli.py keygen")
        return
    
    layers = public_key['num_layers']
    bits = layers * 1024
    breaking_exp = int(bits * 77 / 256)
    
    print(f"✅ Keys Found")
    print(f"   📂 Location: {KEYS_DIR}")
    print()
    print(f"🔒 Security Configuration:")
    print(f"   • Layers: {layers}")
    print(f"   • Security: {bits:,} bits")
    print(f"   • Breaking time: 10^{breaking_exp} years")
    print(f"   • Version: {public_key['version']}")


# ════════════════════════════════════════════════════════════════════════════════════════
# ENCRYPTION/DECRYPTION
# ════════════════════════════════════════════════════════════════════════════════════════

def encrypt_file(input_path: str):
    """Encrypt a file"""
    input_path = Path(input_path)
    
    if not input_path.exists():
        print(f"❌ File not found: {input_path}")
        return
    
    if input_path.suffix == '.qenc':
        print("❌ File is already encrypted!")
        return
    
    public_key = load_public_key()
    if public_key is None:
        print("❌ No keys found! Generate keys first:")
        print("   python cli.py keygen")
        return
    
    output_path = input_path.with_suffix(input_path.suffix + ".qenc")
    
    print("🔒 ENCRYPTING FILE")
    print("=" * 60)
    print(f"   Input:  {input_path}")
    print(f"   Output: {output_path}")
    print(f"   Layers: {public_key['num_layers']}")
    print(f"   Security: {public_key['num_layers'] * 1024:,} bits")
    print("=" * 60)
    print()
    
    # Read file
    print("📖 Reading file...")
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Create metadata
    metadata = {
        'original_name': input_path.name,
        'original_size': len(plaintext),
        'encrypted_at': datetime.now().isoformat(),
    }
    metadata_bytes = json.dumps(metadata).encode()
    combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
    
    # Encrypt
    print("🔐 Encrypting with infinite layers...")
    crypto = InfiniteQuantumEncryption(num_layers=public_key['num_layers'])
    encrypted = crypto.encrypt(combined, public_key)
    
    # Write encrypted file
    print("💾 Writing encrypted file...")
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
    
    print()
    print("✅ ENCRYPTION COMPLETE!")
    print(f"   📄 Encrypted file: {output_path}")
    print(f"   📊 Original size: {len(plaintext):,} bytes")
    print(f"   📊 Encrypted size: {os.path.getsize(output_path):,} bytes")


def decrypt_file(input_path: str):
    """Decrypt a file"""
    input_path = Path(input_path)
    
    if not input_path.exists():
        print(f"❌ File not found: {input_path}")
        return
    
    if input_path.suffix != '.qenc':
        print("❌ File doesn't appear to be encrypted!")
        print("   Encrypted files have .qenc extension")
        return
    
    private_key = load_private_key()
    if private_key is None:
        print("❌ No private key found! Cannot decrypt.")
        return
    
    print("🔓 DECRYPTING FILE")
    print("=" * 60)
    print(f"   Input: {input_path}")
    print("=" * 60)
    print()
    
    # Read encrypted file
    print("📖 Reading encrypted file...")
    with open(input_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC_HEADER:
            print("❌ Not a valid QENC encrypted file!")
            return
        
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
    
    # Decrypt
    print(f"🔐 Decrypting {num_layers} layers...")
    crypto = InfiniteQuantumEncryption(num_layers=num_layers)
    decrypted = crypto.decrypt(encrypted, private_key)
    
    # Parse metadata
    metadata_len = int.from_bytes(decrypted[:4], 'big')
    metadata = json.loads(decrypted[4:4+metadata_len].decode())
    plaintext = decrypted[4+metadata_len:]
    
    # Write decrypted file
    original_name = metadata.get('original_name', 'decrypted_file')
    output_path = input_path.parent / f"decrypted_{original_name}"
    
    print("💾 Writing decrypted file...")
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print()
    print("✅ DECRYPTION COMPLETE!")
    print(f"   📄 Decrypted file: {output_path}")
    print(f"   📊 Original name: {original_name}")
    print(f"   📊 Size: {len(plaintext):,} bytes")


# ════════════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="🔐 Quantum File Encryptor - CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py keygen                  Generate keys (10 layers)
  python cli.py keygen --layers 50      Generate keys (50 layers)
  python cli.py encrypt document.pdf    Encrypt a file
  python cli.py decrypt document.pdf.qenc  Decrypt a file
  python cli.py info                    Show key information
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # keygen command
    keygen_parser = subparsers.add_parser('keygen', help='Generate encryption keys')
    keygen_parser.add_argument('--layers', type=int, default=10,
                               help='Number of encryption layers (default: 10)')
    
    # encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    
    # decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt (.qenc)')
    
    # info command
    subparsers.add_parser('info', help='Show key information')
    
    args = parser.parse_args()
    
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   🔐 QUANTUM FILE ENCRYPTOR - Command Line Interface        ║")
    print("║   Infinite-Layer Quantum-Resistant Encryption               ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    
    if args.command == 'keygen':
        generate_keys(args.layers)
    elif args.command == 'encrypt':
        encrypt_file(args.file)
    elif args.command == 'decrypt':
        decrypt_file(args.file)
    elif args.command == 'info':
        show_info()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
