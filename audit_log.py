"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   📋 AUDIT LOG - Encrypted Security Logging                                 ║
║                                                                              ║
║   All encryption/decryption operations are logged for security audit        ║
║   Logs are encrypted and tamper-evident                                     ║
║                                                                              ║
║   FEATURES:                                                                  ║
║   - Encrypted log storage                                                   ║
║   - Tamper detection via HMAC                                               ║
║   - Log rotation (max entries per file)                                     ║
║   - Search and export capabilities                                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import hashlib
import secrets
import struct
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict
from dataclasses import dataclass, asdict
import hmac

# Add local folder to path
sys.path.insert(0, str(Path(__file__).parent))


# ═══════════════════════════════════════════════════════════════════════════
# LOG ENTRY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class LogEntry:
    """A single audit log entry"""
    timestamp: str
    operation: str  # ENCRYPT, DECRYPT, VERIFY, FAILED_ATTEMPT, etc.
    file_path: str
    file_size: int
    success: bool
    details: str
    user: str
    machine: str
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'LogEntry':
        return cls(**data)


# ═══════════════════════════════════════════════════════════════════════════
# AUDIT LOGGER
# ═══════════════════════════════════════════════════════════════════════════

class AuditLogger:
    """
    Secure audit logging for encryption operations.
    
    All logs are:
    - Encrypted with AES-256-GCM
    - Protected with HMAC for tamper detection
    - Rotated automatically
    """
    
    LOG_MAGIC = b'ALOG'
    LOG_VERSION = 1
    MAX_ENTRIES_PER_FILE = 1000
    
    def __init__(self, log_dir: Path = None, log_key: bytes = None):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory for log files (default: .quantum_logs in user home)
            log_key: 32-byte key for encrypting logs (auto-generated if not provided)
        """
        if log_dir is None:
            log_dir = Path.home() / '.quantum_encryptor_logs'
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Make log directory hidden on Windows
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(self.log_dir), 0x02)
        except:
            pass
        
        # Load or generate log key
        self.key_file = self.log_dir / '.log_key'
        if log_key:
            self.log_key = log_key
        else:
            self.log_key = self._load_or_generate_key()
        
        # Current log file
        self.current_log = self._get_current_log_file()
    
    def _load_or_generate_key(self) -> bytes:
        """Load existing key or generate new one"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                return f.read()
        
        # Generate new key
        key = secrets.token_bytes(32)
        with open(self.key_file, 'wb') as f:
            f.write(key)
        
        # Make key file hidden
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(self.key_file), 0x02)
        except:
            pass
        
        return key
    
    def _get_current_log_file(self) -> Path:
        """Get current log file path"""
        date_str = datetime.now().strftime("%Y-%m")
        return self.log_dir / f"audit_{date_str}.log"
    
    def _encrypt_entry(self, entry: LogEntry) -> bytes:
        """Encrypt a log entry"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("cryptography library required")
        
        # Serialize entry
        entry_json = json.dumps(entry.to_dict()).encode('utf-8')
        
        # Encrypt
        nonce = secrets.token_bytes(12)
        cipher = AESGCM(self.log_key)
        ciphertext = cipher.encrypt(nonce, entry_json, None)
        
        # Add HMAC for tamper detection
        hmac_key = hashlib.sha256(self.log_key + b'hmac').digest()
        entry_hmac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
        
        # Pack: nonce(12) + hmac(32) + ciphertext(variable)
        return nonce + entry_hmac + ciphertext
    
    def _decrypt_entry(self, encrypted: bytes) -> LogEntry:
        """Decrypt a log entry"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("cryptography library required")
        
        # Unpack
        nonce = encrypted[:12]
        stored_hmac = encrypted[12:44]
        ciphertext = encrypted[44:]
        
        # Verify HMAC
        hmac_key = hashlib.sha256(self.log_key + b'hmac').digest()
        computed_hmac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
        
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            raise ValueError("Log entry tampered! HMAC verification failed.")
        
        # Decrypt
        cipher = AESGCM(self.log_key)
        entry_json = cipher.decrypt(nonce, ciphertext, None)
        
        return LogEntry.from_dict(json.loads(entry_json.decode('utf-8')))
    
    def log(self, operation: str, file_path: str, file_size: int = 0,
            success: bool = True, details: str = "") -> None:
        """
        Log an operation.
        
        Args:
            operation: Operation type (ENCRYPT, DECRYPT, VERIFY, etc.)
            file_path: Path to the file involved
            file_size: Size of the file
            success: Whether operation succeeded
            details: Additional details
        """
        import getpass
        import socket
        
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            operation=operation,
            file_path=str(file_path),
            file_size=file_size,
            success=success,
            details=details,
            user=getpass.getuser(),
            machine=socket.gethostname()
        )
        
        encrypted = self._encrypt_entry(entry)
        
        # Append to log file
        with open(self.current_log, 'ab') as f:
            f.write(struct.pack('>I', len(encrypted)))
            f.write(encrypted)
        
        # Check if rotation needed
        self._check_rotation()
    
    def _check_rotation(self) -> None:
        """Check if log needs rotation"""
        entry_count = self.count_entries()
        if entry_count >= self.MAX_ENTRIES_PER_FILE:
            # Rotate to new file with timestamp
            new_name = self.current_log.stem + f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            new_path = self.log_dir / new_name
            self.current_log.rename(new_path)
            self.current_log = self._get_current_log_file()
    
    def count_entries(self) -> int:
        """Count entries in current log file"""
        if not self.current_log.exists():
            return 0
        
        count = 0
        try:
            with open(self.current_log, 'rb') as f:
                while True:
                    length_data = f.read(4)
                    if len(length_data) < 4:
                        break
                    length = struct.unpack('>I', length_data)[0]
                    f.seek(length, 1)  # Skip entry
                    count += 1
        except:
            pass
        
        return count
    
    def read_all(self) -> List[LogEntry]:
        """Read all entries from current log file"""
        entries = []
        
        if not self.current_log.exists():
            return entries
        
        with open(self.current_log, 'rb') as f:
            while True:
                length_data = f.read(4)
                if len(length_data) < 4:
                    break
                
                length = struct.unpack('>I', length_data)[0]
                encrypted = f.read(length)
                
                try:
                    entry = self._decrypt_entry(encrypted)
                    entries.append(entry)
                except Exception as e:
                    # Log corruption detected
                    entries.append(LogEntry(
                        timestamp="CORRUPTED",
                        operation="CORRUPTED",
                        file_path="",
                        file_size=0,
                        success=False,
                        details=str(e),
                        user="",
                        machine=""
                    ))
        
        return entries
    
    def search(self, operation: str = None, file_path: str = None,
               start_date: str = None, end_date: str = None) -> List[LogEntry]:
        """Search log entries by criteria"""
        entries = self.read_all()
        results = []
        
        for entry in entries:
            if operation and entry.operation != operation:
                continue
            if file_path and file_path not in entry.file_path:
                continue
            if start_date and entry.timestamp < start_date:
                continue
            if end_date and entry.timestamp > end_date:
                continue
            results.append(entry)
        
        return results
    
    def export_csv(self, output_path: Path) -> int:
        """Export logs to CSV file"""
        import csv
        
        entries = self.read_all()
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Operation', 'File', 'Size', 
                           'Success', 'Details', 'User', 'Machine'])
            
            for entry in entries:
                writer.writerow([
                    entry.timestamp,
                    entry.operation,
                    entry.file_path,
                    entry.file_size,
                    entry.success,
                    entry.details,
                    entry.user,
                    entry.machine
                ])
        
        return len(entries)
    
    def verify_integrity(self) -> Tuple[int, int]:
        """
        Verify integrity of all log entries.
        
        Returns:
            (valid_count, corrupted_count)
        """
        entries = self.read_all()
        valid = sum(1 for e in entries if e.operation != "CORRUPTED")
        corrupted = len(entries) - valid
        return valid, corrupted


# ═══════════════════════════════════════════════════════════════════════════
# TAMPER DETECTION
# ═══════════════════════════════════════════════════════════════════════════

class TamperDetector:
    """
    Detect tampering of encrypted files.
    
    Creates and verifies HMAC signatures for encrypted files.
    """
    
    SIGNATURE_EXTENSION = '.qsig'
    
    @staticmethod
    def create_signature(file_path: Path, key: bytes) -> Path:
        """
        Create HMAC signature for encrypted file.
        
        Returns path to signature file.
        """
        file_path = Path(file_path)
        sig_path = file_path.with_suffix(file_path.suffix + TamperDetector.SIGNATURE_EXTENSION)
        
        # Calculate HMAC of file contents
        with open(file_path, 'rb') as f:
            file_hash = hmac.new(key, f.read(), hashlib.sha256).digest()
        
        # Store signature with metadata
        sig_data = {
            'file': file_path.name,
            'size': file_path.stat().st_size,
            'created': datetime.now().isoformat(),
            'algorithm': 'HMAC-SHA256',
            'signature': file_hash.hex()
        }
        
        # Encrypt signature data
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = secrets.token_bytes(12)
            cipher = AESGCM(key)
            encrypted_sig = cipher.encrypt(nonce, json.dumps(sig_data).encode(), None)
            
            with open(sig_path, 'wb') as f:
                f.write(b'QSIG')  # Magic
                f.write(struct.pack('>H', 1))  # Version
                f.write(nonce)
                f.write(encrypted_sig)
        except ImportError:
            # Fallback: store plaintext signature
            with open(sig_path, 'w') as f:
                json.dump(sig_data, f)
        
        return sig_path
    
    @staticmethod
    def verify_signature(file_path: Path, key: bytes) -> Tuple[bool, str]:
        """
        Verify file has not been tampered.
        
        Returns:
            (is_valid, message)
        """
        file_path = Path(file_path)
        sig_path = file_path.with_suffix(file_path.suffix + TamperDetector.SIGNATURE_EXTENSION)
        
        if not sig_path.exists():
            return False, "Signature file not found"
        
        # Load signature
        try:
            with open(sig_path, 'rb') as f:
                magic = f.read(4)
                if magic == b'QSIG':
                    # Encrypted signature
                    version = struct.unpack('>H', f.read(2))[0]
                    nonce = f.read(12)
                    encrypted_sig = f.read()
                    
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    cipher = AESGCM(key)
                    sig_json = cipher.decrypt(nonce, encrypted_sig, None)
                    sig_data = json.loads(sig_json.decode())
                else:
                    # Plaintext signature (fallback)
                    f.seek(0)
                    sig_data = json.load(f)
        except Exception as e:
            return False, f"Could not read signature: {e}"
        
        # Calculate current file hash
        with open(file_path, 'rb') as f:
            current_hash = hmac.new(key, f.read(), hashlib.sha256).hexdigest()
        
        # Compare
        stored_hash = sig_data.get('signature', '')
        
        if hmac.compare_digest(current_hash, stored_hash):
            return True, "File integrity verified"
        else:
            return False, "TAMPER DETECTED: File has been modified!"
    
    @staticmethod
    def remove_signature(file_path: Path) -> bool:
        """Remove signature file"""
        sig_path = Path(file_path).with_suffix(
            Path(file_path).suffix + TamperDetector.SIGNATURE_EXTENSION
        )
        if sig_path.exists():
            sig_path.unlink()
            return True
        return False


# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL LOGGER INSTANCE
# ═══════════════════════════════════════════════════════════════════════════

_global_logger = None

def get_logger() -> AuditLogger:
    """Get global audit logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = AuditLogger()
    return _global_logger

def log_operation(operation: str, file_path: str, **kwargs):
    """Quick log function"""
    get_logger().log(operation, file_path, **kwargs)
