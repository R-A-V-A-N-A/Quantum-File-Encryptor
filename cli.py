"""
🔐 QUANTUM FILE ENCRYPTOR - Command Line Interface

Usage:
    python cli.py encrypt <file> [--password <password>]  Encrypt a file
    python cli.py decrypt <file.qenc> --password <password>  Decrypt a file
    python cli.py genkey                                   Generate a random password
    python cli.py info                                     Show security information
"""

import sys
import os
import json
import base64
import secrets
import argparse
from pathlib import Path
from datetime import datetime

# Fix UTF-8 encoding for Windows console
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, OSError):
        pass  # Older Python versions

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
        print("❌ Error: No encryption module found!")
        print("   Make sure secure_vault_quantum.py or secure_vault.py exists.")
        sys.exit(1)


# ════════════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════════════

MAGIC_HEADER = b"QVLT"  # Quantum VauLT
VERSION = 2


# ════════════════════════════════════════════════════════════════════════════════════════
# FILE ENCRYPTOR
# ════════════════════════════════════════════════════════════════════════════════════════

class FileEncryptor:
    """Handles file encryption/decryption"""
    
    def __init__(self):
        if QUANTUM_AVAILABLE:
            self.vault = QuantumSecureVault()
        else:
            self.vault = SecureVault()
    
    def generate_password(self) -> str:
        """Generate a secure random password"""
        return base64.b64encode(secrets.token_bytes(32)).decode('ascii')
    
    def encrypt_file(self, input_path: Path, password: str, output_path: Path = None) -> tuple:
        """Encrypt a file with password"""
        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + ".qenc")
        
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
        combined = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + plaintext
        
        # Encrypt
        encrypted_data = self.vault.encrypt(combined, password)
        
        # Write encrypted file
        with open(output_path, 'wb') as f:
            f.write(MAGIC_HEADER)
            f.write(VERSION.to_bytes(2, 'big'))
            f.write(len(encrypted_data).to_bytes(8, 'big'))
            f.write(encrypted_data)
        
        return True, output_path
    
    def decrypt_file(self, input_path: Path, password: str, output_path: Path = None) -> tuple:
        """Decrypt a file with password"""
        with open(input_path, 'rb') as f:
            magic = f.read(4)
            if magic != MAGIC_HEADER:
                return False, "Not a valid QVLT encrypted file!"
            
            version = int.from_bytes(f.read(2), 'big')
            enc_len = int.from_bytes(f.read(8), 'big')
            encrypted_data = f.read(enc_len)
        
        # Decrypt
        try:
            decrypted = self.vault.decrypt(encrypted_data, password)
        except ValueError:
            return False, "Wrong password!"
        
        # Parse metadata
        metadata_len = int.from_bytes(decrypted[:4], 'big')
        metadata = json.loads(decrypted[4:4+metadata_len].decode())
        plaintext = decrypted[4+metadata_len:]
        
        # Determine output path
        if output_path is None:
            original_name = metadata.get('original_name', 'decrypted_file')
            output_path = input_path.parent / f"decrypted_{original_name}"
        
        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return True, output_path


# ════════════════════════════════════════════════════════════════════════════════════════
# CLI FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════════════

def generate_key():
    """Generate a secure random password"""
    encryptor = FileEncryptor()
    password = encryptor.generate_password()
    
    print()
    print("🔑 Generated Encryption Key:")
    print("=" * 60)
    print(f"  {password}")
    print("=" * 60)
    print()
    print("⚠️  IMPORTANT: Save this key somewhere safe!")
    print("   You will need it to decrypt your files.")


def show_info():
    """Show security information"""
    print()
    print("=" * 60)
    print("   🔐 QUANTUM FILE ENCRYPTOR - Security Information")
    print("=" * 60)
    print()
    
    if QUANTUM_AVAILABLE:
        print("✅ Post-Quantum Encryption ENABLED")
        print()
        print("🔒 Security Features:")
        print("   • ML-KEM-1024 post-quantum key encapsulation (FIPS 203)")
        print("   • AES-256-GCM authenticated encryption")
        print("   • Argon2id memory-hard key derivation")
        print("   • Hybrid encryption: Classical + Post-Quantum")
        print("   • NIST Level 5 security")
        print("   • 'Harvest Now, Decrypt Later' protection")
    else:
        print("⚠️  Standard Encryption Mode (Quantum not available)")
        print()
        print("🔒 Security Features:")
        print("   • AES-256-GCM authenticated encryption")
        print("   • Argon2id memory-hard key derivation")
        print("   • 256-bit security level")
    print()


def encrypt_file(input_path: str, password: str = None):
    """Encrypt a file"""
    input_path = Path(input_path)
    
    if not input_path.exists():
        print(f"❌ File not found: {input_path}")
        return
    
    if input_path.suffix == '.qenc':
        print("❌ File is already encrypted!")
        return
    
    encryptor = FileEncryptor()
    
    # Generate password if not provided
    if not password:
        password = encryptor.generate_password()
        print()
        print("🔑 Generated Key (SAVE THIS!):")
        print("=" * 60)
        print(f"  {password}")
        print("=" * 60)
        print()
    
    output_path = input_path.with_suffix(input_path.suffix + ".qenc")
    
    print("🔒 ENCRYPTING FILE")
    print("=" * 60)
    print(f"   Input:  {input_path}")
    print(f"   Output: {output_path}")
    print(f"   Mode:   {'Quantum-Resistant' if QUANTUM_AVAILABLE else 'Standard AES-256'}")
    print("=" * 60)
    print()
    
    success, result = encryptor.encrypt_file(input_path, password, output_path)
    
    if success:
        print("✅ ENCRYPTION COMPLETE!")
        print(f"   📄 Encrypted file: {result}")
        print(f"   📊 Original size: {input_path.stat().st_size:,} bytes")
        print(f"   📊 Encrypted size: {result.stat().st_size:,} bytes")
    else:
        print(f"❌ Encryption failed: {result}")


def decrypt_file(input_path: str, password: str):
    """Decrypt a file"""
    input_path = Path(input_path)
    
    if not input_path.exists():
        print(f"❌ File not found: {input_path}")
        return
    
    if input_path.suffix != '.qenc':
        print("❌ File doesn't appear to be encrypted!")
        print("   Encrypted files have .qenc extension")
        return
    
    if not password:
        print("❌ Password is required for decryption!")
        return
    
    encryptor = FileEncryptor()
    
    print("🔓 DECRYPTING FILE")
    print("=" * 60)
    print(f"   Input: {input_path}")
    print("=" * 60)
    print()
    
    success, result = encryptor.decrypt_file(input_path, password)
    
    if success:
        print("✅ DECRYPTION COMPLETE!")
        print(f"   📄 Decrypted file: {result}")
        print(f"   📊 Size: {result.stat().st_size:,} bytes")
    else:
        print(f"❌ Decryption failed: {result}")


# ════════════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="🔐 Quantum File Encryptor - CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py encrypt document.pdf            Encrypt (auto-generates key)
  python cli.py encrypt doc.pdf -p mypassword   Encrypt with password
  python cli.py decrypt doc.pdf.qenc -p key     Decrypt with key
  python cli.py genkey                          Generate a random key
  python cli.py info                            Show security information
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # genkey command
    subparsers.add_parser('genkey', help='Generate a random encryption key')
    
    # encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('-p', '--password', help='Encryption password/key')
    
    # decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt (.qenc)')
    decrypt_parser.add_argument('-p', '--password', required=True, help='Decryption password/key')
    
    # info command
    subparsers.add_parser('info', help='Show security information')
    
    args = parser.parse_args()
    
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    if QUANTUM_AVAILABLE:
        print("║   🔐 QUANTUM FILE ENCRYPTOR - Post-Quantum Hybrid Encryption║")
    else:
        print("║   🔐 QUANTUM FILE ENCRYPTOR - Standard Edition              ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()
    
    if args.command == 'genkey':
        generate_key()
    elif args.command == 'encrypt':
        encrypt_file(args.file, args.password)
    elif args.command == 'decrypt':
        decrypt_file(args.file, args.password)
    elif args.command == 'info':
        show_info()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
