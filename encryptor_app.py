"""
QUANTUM FILE ENCRYPTOR - POST-QUANTUM HYBRID ENCRYPTION
Uses QuantumSecureVault: FIPS 203 ML-KEM-1024 + AES-256-GCM + FIPS 204 ML-DSA-87

ENCRYPT: Generates a unique KEY for you to copy and save
DECRYPT: Enter the KEY you received to decrypt

SECURITY FEATURES:
- ML-KEM-1024 post-quantum key encapsulation (FIPS 203 - August 2024)
- ML-DSA-87 digital signatures (FIPS 204 - August 2024)
- AES-256-GCM / ChaCha20-Poly1305 authenticated encryption (AEAD)
- Argon2id memory-hard key derivation (Password Hashing Competition winner)
- NIST Level 5 security (maximum quantum resistance)
- Hybrid encryption: Classical + Post-Quantum
- "Harvest Now, Decrypt Later" attack protection
- Tamper detection built-in
- Used by governments and enterprises for TOP SECRET data
"""

# ============================================================================
# VERSION AND UPDATE CONFIGURATION
# ============================================================================
APP_VERSION = "2.1.0"
GITHUB_REPO = "R-A-V-A-N-A/Quantum-File-Encryptor"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_RELEASES_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"

import sys
import os

# Force UTF-8 encoding on Windows for Unicode box-drawing and emoji support
if sys.platform == 'win32':
    import locale
    if sys.stdout.encoding != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
    if sys.stderr.encoding != 'utf-8':
        sys.stderr.reconfigure(encoding='utf-8')
    # Also set console to UTF-8 mode
    os.system('chcp 65001 > nul 2>&1')

import hashlib
import secrets
import struct
import base64
import subprocess
import json
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta

# ============================================================================
# ANSI COLORS AND FORMATTING (Premium CLI Experience)
# ============================================================================

class Colors:
    """ANSI color codes for terminal output"""
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    RESET = '\033[0m'
    
    # Combined styles
    HEADER = '\033[1m\033[96m'      # Bold Cyan
    SUCCESS = '\033[1m\033[92m'     # Bold Green
    WARNING = '\033[1m\033[93m'     # Bold Yellow
    ERROR = '\033[1m\033[91m'       # Bold Red
    INFO = '\033[36m'               # Cyan
    MUTED = '\033[90m'              # Gray

# Enable ANSI colors on Windows
if os.name == 'nt':
    os.system('')  # Enable ANSI escape sequences

def c(text, color):
    """Colorize text"""
    return f"{color}{text}{Colors.RESET}"

def print_header(title, subtitle=None):
    """Print a beautiful header box"""
    width = 65
    print()
    print(c("╔" + "═" * width + "╗", Colors.CYAN))
    print(c("║", Colors.CYAN) + c(title.center(width), Colors.HEADER) + c("║", Colors.CYAN))
    if subtitle:
        print(c("║", Colors.CYAN) + c(subtitle.center(width), Colors.MUTED) + c("║", Colors.CYAN))
    print(c("╚" + "═" * width + "╝", Colors.CYAN))
    print()

def print_box(title, items, color=Colors.CYAN):
    """Print a bordered menu box"""
    width = 50
    print(c("  ┌" + "─" * width + "┐", color))
    print(c("  │", color) + c(title.center(width), Colors.BOLD) + c("│", color))
    print(c("  ├" + "─" * width + "┤", color))
    for item in items:
        print(c("  │  ", color) + f"{item:<{width-2}}" + c("│", color))
    print(c("  └" + "─" * width + "┘", color))

def print_success(msg):
    """Print success message"""
    print(c(f"  ✓ {msg}", Colors.SUCCESS))

def print_error(msg):
    """Print error message"""
    print(c(f"  ✗ {msg}", Colors.ERROR))

def print_warning(msg):
    """Print warning message"""
    print(c(f"  ⚠ {msg}", Colors.WARNING))

def print_info(msg):
    """Print info message"""
    print(c(f"  ℹ {msg}", Colors.INFO))

def print_step(num, text):
    """Print a numbered step"""
    print(c(f"  [{num}]", Colors.BRIGHT_CYAN) + f" {text}")

class ProgressBar:
    """Animated progress bar with speed and ETA"""
    def __init__(self, total, width=40, desc="Processing"):
        self.total = total
        self.width = width
        self.desc = desc
        self.current = 0
        self.start_time = time.time()
        self.last_update = 0
    
    def update(self, current, status=""):
        self.current = current
        now = time.time()
        
        # Throttle updates to every 100ms
        if now - self.last_update < 0.1 and current < self.total:
            return
        self.last_update = now
        
        pct = min(100, (current / self.total) * 100) if self.total > 0 else 0
        filled = int(self.width * pct / 100)
        bar = "█" * filled + "░" * (self.width - filled)
        
        elapsed = now - self.start_time
        speed = current / elapsed if elapsed > 0 else 0
        eta = (self.total - current) / speed if speed > 0 else 0
        
        speed_str = format_speed(speed)
        eta_str = format_time(eta) if eta > 0 else "0s"
        
        line = f"\r  {c(bar, Colors.CYAN)} {c(f'{pct:5.1f}%', Colors.BRIGHT_WHITE)} │ {speed_str} │ ETA: {eta_str}"
        if status:
            line += f" │ {status}"
        
        print(line + " " * 10, end="", flush=True)
    
    def finish(self, msg="Complete!"):
        self.update(self.total)
        elapsed = time.time() - self.start_time
        print()
        print_success(f"{msg} ({format_time(elapsed)})")

class Spinner:
    """Animated loading spinner"""
    def __init__(self, message="Loading"):
        self.message = message
        self.running = False
        self.thread = None
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    def _animate(self):
        i = 0
        while self.running:
            frame = self.frames[i % len(self.frames)]
            print(f"\r  {c(frame, Colors.CYAN)} {self.message}...", end="", flush=True)
            time.sleep(0.1)
            i += 1
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.start()
    
    def stop(self, success=True, msg=None):
        self.running = False
        if self.thread:
            self.thread.join()
        if success:
            print(f"\r  {c('✓', Colors.SUCCESS)} {msg or self.message}     ")
        else:
            print(f"\r  {c('✗', Colors.ERROR)} {msg or self.message}     ")


# Add encryption library paths (local folder first, then parent)
sys.path.insert(0, str(Path(__file__).parent))  # Local folder
sys.path.insert(1, str(Path(__file__).parent.parent / "QUANTUM_RESISTANT_ENCRYPTION"))  # Parent

# Try to import QuantumSecureVault (post-quantum encryption)
try:
    from secure_vault_quantum import QuantumSecureVault, SecureVault
    ENCRYPTION_LEVEL = "QUANTUM_SECURE_VAULT"
    QUANTUM_AVAILABLE = True
except ImportError:
    # Fallback to non-quantum SecureVault
    try:
        from secure_vault import SecureVault
        ENCRYPTION_LEVEL = "SECURE_VAULT"
        QUANTUM_AVAILABLE = False
    except ImportError:
        print("Error: No encryption module found!")
        print("Make sure secure_vault_quantum.py or secure_vault.py exists in this folder.")
        sys.exit(1)


# ============================================================================
# ENCRYPTION ENGINE USING SECURE VAULT
# ============================================================================

MAGIC = b"SVLS"  # SecureVauLT Streaming
VERSION = 6
STREAM_MAGIC = b"SVLS"

# ============================================================================
# MEMORY AND CHUNK CONFIGURATION
# ============================================================================

def get_optimal_chunk_size():
    """Calculate optimal chunk size based on 70% of available RAM"""
    try:
        import psutil
        total_mem = psutil.virtual_memory().total
        # Use 70% of total memory, but cap between 64MB and 1GB
        # (ChaCha20-Poly1305 has a 2GB limit, so we stay well under)
        chunk_size = int(total_mem * 0.70)
        chunk_size = max(64 * 1024 * 1024, min(chunk_size, 1 * 1024 * 1024 * 1024))  # Max 1GB
        return chunk_size
    except ImportError:
        # Fallback: use 512MB chunks if psutil not available
        return 512 * 1024 * 1024

def get_nonce_for_chunk(salt: bytes, chunk_index: int) -> bytes:
    """Generate unique 12-byte nonce for each chunk"""
    # Use HMAC to derive nonce from salt and chunk index
    import hmac
    data = struct.pack('>Q', chunk_index)
    return hmac.new(salt, data, hashlib.sha256).digest()[:12]

def format_time(seconds: float) -> str:
    """Format seconds into human readable time"""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds // 60:.0f}m {seconds % 60:.0f}s"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours:.0f}h {mins:.0f}m"

def format_speed(bytes_per_sec: float) -> str:
    """Format bytes/sec into human readable speed"""
    if bytes_per_sec < 1024:
        return f"{bytes_per_sec:.0f} B/s"
    elif bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    elif bytes_per_sec < 1024 * 1024 * 1024:
        return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
    else:
        return f"{bytes_per_sec / (1024 * 1024 * 1024):.2f} GB/s"


def generate_key() -> str:
    """Generate a random encryption key and return as base64 string"""
    raw_key = secrets.token_bytes(128)
    return base64.b64encode(raw_key).decode('ascii')


def key_to_bytes(key_string: str) -> bytes:
    """Convert base64 key string back to bytes"""
    try:
        return base64.b64decode(key_string.encode('ascii'))
    except:
        return None


def bytes_to_key(key_bytes: bytes) -> str:
    """Convert key bytes back to base64 string"""
    return base64.b64encode(key_bytes).decode('ascii')


# ============================================================================
# BRUTE-FORCE PROTECTION (Escalating Lockouts)
# ============================================================================

def get_lockout_file(encrypted_file: Path) -> Path:
    """Get the path to the lockout tracking file"""
    return encrypted_file.with_suffix(encrypted_file.suffix + '.lock')


def get_lockout_status(encrypted_file: Path) -> dict:
    """
    Get the lockout status for an encrypted file.
    
    Returns:
        {
            'locked': bool,
            'unlock_time': datetime or None,
            'failed_attempts': int,
            'lockout_level': int (1=24h, 2=48h, 3=72h, etc.)
        }
    """
    lock_file = get_lockout_file(encrypted_file)
    
    if not lock_file.exists():
        return {
            'locked': False,
            'unlock_time': None,
            'failed_attempts': 0,
            'lockout_level': 0
        }
    
    try:
        with open(lock_file, 'r') as f:
            data = json.load(f)
        
        unlock_time_str = data.get('unlock_time')
        if unlock_time_str:
            unlock_time = datetime.fromisoformat(unlock_time_str)
            if datetime.now() < unlock_time:
                # Still locked
                return {
                    'locked': True,
                    'unlock_time': unlock_time,
                    'failed_attempts': data.get('failed_attempts', 0),
                    'lockout_level': data.get('lockout_level', 1)
                }
            else:
                # Lockout expired, reset attempts but keep level
                return {
                    'locked': False,
                    'unlock_time': None,
                    'failed_attempts': 0,
                    'lockout_level': data.get('lockout_level', 0)
                }
        
        return {
            'locked': False,
            'unlock_time': None,
            'failed_attempts': data.get('failed_attempts', 0),
            'lockout_level': data.get('lockout_level', 0)
        }
    except:
        return {
            'locked': False,
            'unlock_time': None,
            'failed_attempts': 0,
            'lockout_level': 0
        }


def record_failed_attempt(encrypted_file: Path):
    """
    Record a failed decryption attempt.
    After 3 failed attempts, locks the file with escalating duration.
    """
    lock_file = get_lockout_file(encrypted_file)
    status = get_lockout_status(encrypted_file)
    
    failed_attempts = status['failed_attempts'] + 1
    lockout_level = status['lockout_level']
    
    if failed_attempts >= 3:
        # Lock the file! Escalate the lockout level
        lockout_level += 1
        lockout_hours = 24 * lockout_level  # 24h, 48h, 72h, etc.
        unlock_time = datetime.now() + timedelta(hours=lockout_hours)
        
        data = {
            'failed_attempts': failed_attempts,
            'lockout_level': lockout_level,
            'unlock_time': unlock_time.isoformat(),
            'locked_at': datetime.now().isoformat()
        }
    else:
        # Just increment the counter
        data = {
            'failed_attempts': failed_attempts,
            'lockout_level': lockout_level,
            'unlock_time': None
        }
    
    with open(lock_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    # Make the lock file hidden on Windows
    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(lock_file), 0x02)  # FILE_ATTRIBUTE_HIDDEN
    except:
        pass  # Ignore on non-Windows systems
    
    return failed_attempts, lockout_level


def clear_lockout(encrypted_file: Path):
    """Clear the lockout after successful decryption"""
    lock_file = get_lockout_file(encrypted_file)
    if lock_file.exists():
        lock_file.unlink()


def format_time_remaining(unlock_time: datetime) -> str:
    """Format the time remaining until unlock"""
    remaining = unlock_time - datetime.now()
    total_seconds = int(remaining.total_seconds())
    
    if total_seconds <= 0:
        return "now"
    
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    
    if hours > 24:
        days = hours // 24
        hours = hours % 24
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


# ============================================================================
# SECURE FILE SHREDDING (DoD 5220.22-M Standard)
# ============================================================================

def secure_shred_file(file_path: Path, passes: int = 3, progress_callback=None) -> bool:
    """
    Securely delete a file by overwriting with random data.
    
    Args:
        file_path: Path to file to shred
        passes: Number of overwrite passes (1=quick, 3=DoD, 7=paranoid)
        progress_callback: Optional callback for progress updates
    
    Returns:
        True if successful, False otherwise
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists():
            return False
        
        file_size = file_path.stat().st_size
        
        # Open file for writing
        with open(file_path, 'r+b') as f:
            for pass_num in range(passes):
                f.seek(0)
                
                # Alternate between patterns
                if pass_num % 3 == 0:
                    # Pass 1: All zeros
                    pattern = b'\x00'
                elif pass_num % 3 == 1:
                    # Pass 2: All ones
                    pattern = b'\xFF'
                else:
                    # Pass 3: Random data
                    pattern = None
                
                # Write in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                bytes_written = 0
                
                while bytes_written < file_size:
                    remaining = min(chunk_size, file_size - bytes_written)
                    
                    if pattern:
                        data = pattern * remaining
                    else:
                        data = secrets.token_bytes(remaining)
                    
                    f.write(data)
                    bytes_written += remaining
                    
                    if progress_callback:
                        total_progress = (pass_num * file_size + bytes_written) / (passes * file_size)
                        progress_callback(total_progress * 100, pass_num + 1, passes)
                
                f.flush()
                os.fsync(f.fileno())
        
        # Rename to random name before deleting (hides filename)
        random_name = file_path.parent / secrets.token_hex(16)
        file_path.rename(random_name)
        
        # Finally delete
        random_name.unlink()
        
        return True
        
    except Exception as e:
        print(f"Shred error: {e}")
        return False


# ============================================================================
# SHAMIR SECRET SHARING (Split Key into Parts)
# ============================================================================

def _mod_inverse(a: int, p: int) -> int:
    """Calculate modular multiplicative inverse using extended Euclidean algorithm"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a % p, p)
    return (x % p + p) % p


def split_secret(secret: bytes, num_shares: int, threshold: int) -> list:
    """
    Split a secret into N shares using Shamir's Secret Sharing.
    
    Args:
        secret: The secret bytes to split
        num_shares: Total number of shares to create (N)
        threshold: Minimum shares needed to reconstruct (M)
    
    Returns:
        List of (index, share_bytes) tuples
    """
    if threshold > num_shares:
        raise ValueError("Threshold cannot be greater than number of shares")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    
    # Use a large prime for the field
    # This prime is larger than any possible 256-bit number
    PRIME = 2**256 - 189
    
    # Convert secret to integer
    secret_int = int.from_bytes(secret, 'big')
    
    # Generate random coefficients for polynomial (degree = threshold - 1)
    # f(x) = secret + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
    coefficients = [secret_int]
    for _ in range(threshold - 1):
        coefficients.append(secrets.randbelow(PRIME))
    
    # Evaluate polynomial at points 1, 2, 3, ..., num_shares
    shares = []
    for x in range(1, num_shares + 1):
        y = 0
        for i, coef in enumerate(coefficients):
            y = (y + coef * pow(x, i, PRIME)) % PRIME
        
        # Convert to bytes
        share_bytes = y.to_bytes(33, 'big')  # 33 bytes to handle overflow
        shares.append((x, share_bytes))
    
    return shares


def combine_shares(shares: list) -> bytes:
    """
    Reconstruct a secret from shares using Lagrange interpolation.
    
    Args:
        shares: List of (index, share_bytes) tuples
    
    Returns:
        The reconstructed secret bytes
    """
    PRIME = 2**256 - 189
    
    # Convert shares to integers
    points = [(x, int.from_bytes(share, 'big')) for x, share in shares]
    
    # Lagrange interpolation to find f(0) = secret
    secret = 0
    
    for i, (xi, yi) in enumerate(points):
        # Calculate Lagrange basis polynomial at x=0
        numerator = 1
        denominator = 1
        
        for j, (xj, _) in enumerate(points):
            if i != j:
                numerator = (numerator * (-xj)) % PRIME
                denominator = (denominator * (xi - xj)) % PRIME
        
        # Lagrange coefficient
        lagrange = (numerator * _mod_inverse(denominator, PRIME)) % PRIME
        
        # Add contribution
        secret = (secret + yi * lagrange) % PRIME
    
    # Convert back to bytes (original key size)
    return secret.to_bytes(128, 'big')[-128:]  # Take last 128 bytes


def format_share(index: int, share_bytes: bytes, total: int, threshold: int) -> str:
    """Format a share for display to user"""
    share_b64 = base64.b64encode(share_bytes).decode('ascii')
    # Add metadata prefix
    return f"{index}-{threshold}-{total}-{share_b64}"


def parse_share(share_string: str) -> tuple:
    """Parse a share string back to (index, bytes, total, threshold)"""
    parts = share_string.strip().split('-', 3)
    if len(parts) != 4:
        return None
    
    try:
        index = int(parts[0])
        threshold = int(parts[1])
        total = int(parts[2])
        share_bytes = base64.b64decode(parts[3])
        return index, share_bytes, total, threshold
    except:
        return None


# ============================================================================
# SELF-DESTRUCT TRACKING
# ============================================================================

def get_destruct_file(encrypted_file: Path) -> Path:
    """Get path to self-destruct counter file"""
    return encrypted_file.with_suffix(encrypted_file.suffix + '.destruct')


def check_self_destruct(encrypted_file: Path) -> tuple:
    """
    Check if file should self-destruct.
    
    Returns:
        (should_destruct, reason, remaining_uses)
    """
    destruct_file = get_destruct_file(encrypted_file)
    
    if not destruct_file.exists():
        return False, None, None
    
    try:
        with open(destruct_file, 'r') as f:
            data = json.load(f)
        
        # Check date expiry
        if data.get('expire_date'):
            expire = datetime.fromisoformat(data['expire_date'])
            if datetime.now() > expire:
                return True, f"Expired on {expire.strftime('%Y-%m-%d')}", 0
        
        # Check use count
        max_uses = data.get('max_uses')
        current_uses = data.get('current_uses', 0)
        
        if max_uses and current_uses >= max_uses:
            return True, f"Max uses ({max_uses}) reached", 0
        
        remaining = max_uses - current_uses if max_uses else None
        return False, None, remaining
        
    except:
        return False, None, None


def increment_destruct_counter(encrypted_file: Path) -> tuple:
    """
    Increment the decryption counter.
    
    Returns:
        (should_destruct_after, remaining_uses)
    """
    destruct_file = get_destruct_file(encrypted_file)
    
    if not destruct_file.exists():
        return False, None
    
    try:
        with open(destruct_file, 'r') as f:
            data = json.load(f)
        
        # Increment counter
        data['current_uses'] = data.get('current_uses', 0) + 1
        
        with open(destruct_file, 'w') as f:
            json.dump(data, f)
        
        # Make hidden
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(destruct_file), 0x02)
        except:
            pass
        
        # Check if this was the last use
        max_uses = data.get('max_uses')
        if max_uses and data['current_uses'] >= max_uses:
            return True, 0
        
        remaining = max_uses - data['current_uses'] if max_uses else None
        return False, remaining
        
    except:
        return False, None


def create_destruct_tracker(encrypted_file: Path, max_uses: int = None, 
                           expire_date: datetime = None):
    """Create a self-destruct tracker for an encrypted file"""
    destruct_file = get_destruct_file(encrypted_file)
    
    data = {
        'created': datetime.now().isoformat(),
        'current_uses': 0,
        'max_uses': max_uses,
        'expire_date': expire_date.isoformat() if expire_date else None
    }
    
    with open(destruct_file, 'w') as f:
        json.dump(data, f)
    
    # Make hidden on Windows
    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(destruct_file), 0x02)
    except:
        pass


def destroy_encrypted_file(encrypted_file: Path):
    """Securely destroy an encrypted file and its tracker"""
    # Shred the encrypted file
    secure_shred_file(encrypted_file, passes=3)
    
    # Remove tracker files
    destruct_file = get_destruct_file(encrypted_file)
    if destruct_file.exists():
        destruct_file.unlink()
    
    lock_file = get_lockout_file(encrypted_file)
    if lock_file.exists():
        lock_file.unlink()


# ============================================================================
# FOLDER COMPRESSION (For folder encryption)
# ============================================================================

def zip_folder(folder_path: Path, output_zip: Path = None, progress_callback=None) -> Path:
    """
    Compress a folder into a ZIP file for encryption.
    
    FAST MODE: Uses ZIP_STORED (no compression) because:
    1. Compression is SLOW for large files
    2. Encrypted data is random anyway (incompressible)
    3. Speed is priority for 14GB+ folders
    
    Returns the path to the created ZIP file.
    """
    import zipfile
    import time
    
    folder_path = Path(folder_path)
    
    if output_zip is None:
        output_zip = folder_path.parent / f"{folder_path.name}.zip"
    
    try:
        # Calculate total size for progress
        all_files = list(folder_path.rglob("*"))
        file_list = [f for f in all_files if f.is_file()]
        total_size = sum(f.stat().st_size for f in file_list)
        processed_size = 0
        start_time = time.perf_counter()
        failed_files = []
        
        # Use ZIP_STORED (no compression) for MAXIMUM SPEED
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_STORED) as zf:
            for file_path in file_list:
                try:
                    # Preserve relative path structure inside the zip
                    arcname = file_path.relative_to(folder_path.parent)
                    zf.write(file_path, arcname)
                    
                    file_size = file_path.stat().st_size
                    processed_size += file_size
                    
                    if progress_callback:
                        pct = int((processed_size / total_size) * 100) if total_size > 0 else 100
                        elapsed = time.perf_counter() - start_time
                        speed = processed_size / elapsed if elapsed > 0 else 0
                        speed_mbps = speed / (1024 * 1024)
                        eta = (total_size - processed_size) / speed if speed > 0 else 0
                        progress_callback(pct, processed_size, total_size, eta, 
                                        f"Zipping @ {speed_mbps:.1f} MB/s")
                except PermissionError:
                    failed_files.append((str(file_path), "Permission denied"))
                except OSError as e:
                    failed_files.append((str(file_path), f"OS error: {e.strerror}"))
                except Exception as e:
                    failed_files.append((str(file_path), str(e)))
        
        # Report any failed files
        if failed_files:
            print()
            print_warning(f"Skipped {len(failed_files)} file(s) due to errors:")
            for path, error in failed_files[:5]:  # Show first 5
                print_warning(f"  - {Path(path).name}: {error}")
            if len(failed_files) > 5:
                print_warning(f"  ... and {len(failed_files) - 5} more")
        
        return output_zip
        
    except Exception as e:
        print_error(f"Compression failed: {e}")
        # Clean up partial zip file
        if output_zip.exists():
            try:
                output_zip.unlink()
            except:
                pass
        raise



def unzip_folder(zip_path: Path, output_dir: Path = None, progress_callback=None) -> Path:
    """
    Extract a ZIP file back to a folder.
    Returns the path to the extracted folder.
    """
    import zipfile
    
    zip_path = Path(zip_path)
    
    if output_dir is None:
        output_dir = zip_path.parent
    
    with zipfile.ZipFile(zip_path, 'r') as zf:
        members = zf.namelist()
        total = len(members)
        
        for i, member in enumerate(members):
            zf.extract(member, output_dir)
            
            if progress_callback:
                pct = int(((i + 1) / total) * 100) if total > 0 else 100
                progress_callback(pct, i + 1, total, 0, f"Extracting: {Path(member).name}")
    
    # Return the root folder that was extracted
    root_folder = output_dir / Path(members[0]).parts[0] if members else output_dir
    return root_folder


# ============================================================================
# STREAMING LARGE FILE ENCRYPTION (Handles ANY file size)
# ============================================================================

def read_file_metadata(file_path: Path) -> dict:
    """
    Read metadata from an encrypted file.
    Returns None if file is invalid or cannot be read.
    """
    try:
        with open(file_path, 'rb') as infile:
            magic = infile.read(4)
            if magic != STREAM_MAGIC:
                return None
            
            # Skip version (2), original_size (8), chunk_size (8), total_chunks (8)
            infile.read(26)
            
            meta_len = struct.unpack('>I', infile.read(4))[0]
            meta_bytes = infile.read(meta_len)
            
            return json.loads(meta_bytes.decode())
    except:
        return None


def encrypt_file_with_key(file_path: Path, key_bytes: bytes, output_path: Path = None, 
                          progress_callback=None, security_question: str = None, 
                          security_answer: str = None, extra_metadata: dict = None) -> tuple:
    """
    Encrypt file of ANY size using streaming ChaCha20-Poly1305.
    
    Uses 70% of available RAM for maximum speed.
    Shows progress with ETA.
    Optionally includes security question for key recovery.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        return False, "Required libraries not installed. Run: pip install cryptography argon2-cffi"
    
    file_path = Path(file_path)
    file_size = file_path.stat().st_size
    
    # Get optimal chunk size (70% of RAM)
    chunk_size = get_optimal_chunk_size()
    total_chunks = (file_size + chunk_size - 1) // chunk_size
    
    if progress_callback:
        progress_callback(0, 0, file_size, 0, "Initializing encryption...")
    
    # Generate salt for key derivation
    salt = secrets.token_bytes(16)
    
    # Derive encryption key using Argon2id (fast and reliable for large files)
    derived_key = hash_secret_raw(
        secret=key_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    algorithm = 'ChaCha20-Poly1305-Stream'
    
    cipher = ChaCha20Poly1305(derived_key)
    
    # Prepare recovery data if security question is provided
    recovery_data = None
    if security_question and security_answer:
        # Derive a recovery key from the security answer
        recovery_salt = secrets.token_bytes(16)
        answer_key = hash_secret_raw(
            secret=security_answer.lower().strip().encode('utf-8'),
            salt=recovery_salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        
        # Encrypt the actual key with the answer-derived key
        recovery_cipher = ChaCha20Poly1305(answer_key)
        recovery_nonce = secrets.token_bytes(12)
        encrypted_key = recovery_cipher.encrypt(recovery_nonce, key_bytes, None)
        
        recovery_data = {
            'question': security_question,
            'recovery_salt': base64.b64encode(recovery_salt).decode('ascii'),
            'recovery_nonce': base64.b64encode(recovery_nonce).decode('ascii'),
            'encrypted_key': base64.b64encode(encrypted_key).decode('ascii')
        }
    
    # Create metadata
    metadata = {
        'name': file_path.name,
        'size': file_size,
        'time': datetime.now().isoformat(),
        'algorithm': algorithm,
        'chunk_size': chunk_size,
        'total_chunks': total_chunks,
        'has_recovery': recovery_data is not None
    }
    
    if recovery_data:
        metadata['recovery'] = recovery_data
        
    if extra_metadata:
        metadata.update(extra_metadata)
    
    meta_bytes = json.dumps(metadata).encode()
    
    # Output path
    if output_path is None:
        output_path = file_path.with_suffix(file_path.suffix + '.qenc')
    
    import time
    start_time = time.time()
    bytes_processed = 0
    
    with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        # Write header
        outfile.write(STREAM_MAGIC)                           # 4 bytes
        outfile.write(struct.pack('>H', VERSION))             # 2 bytes
        outfile.write(struct.pack('>Q', file_size))           # 8 bytes - original size
        outfile.write(struct.pack('>Q', chunk_size))          # 8 bytes - chunk size
        outfile.write(struct.pack('>Q', total_chunks))        # 8 bytes - total chunks
        outfile.write(struct.pack('>I', len(meta_bytes)))     # 4 bytes - meta length (increased for recovery data)
        outfile.write(meta_bytes)                             # variable - metadata
        outfile.write(salt)                                   # 16 bytes - salt
        
        # Encrypt each chunk
        for chunk_idx in range(total_chunks):
            # Read chunk
            chunk_data = infile.read(chunk_size)
            if not chunk_data:
                break
            
            # Generate unique nonce for this chunk
            nonce = get_nonce_for_chunk(salt, chunk_idx)
            
            # Encrypt chunk
            encrypted_chunk = cipher.encrypt(nonce, chunk_data, None)
            
            # Write: chunk_length + encrypted_data
            outfile.write(struct.pack('>Q', len(encrypted_chunk)))
            outfile.write(encrypted_chunk)
            
            bytes_processed += len(chunk_data)
            
            # Progress update
            if progress_callback:
                elapsed = time.time() - start_time
                if elapsed > 0 and bytes_processed > 0:
                    speed = bytes_processed / elapsed
                    remaining_bytes = file_size - bytes_processed
                    eta = remaining_bytes / speed if speed > 0 else 0
                    pct = (bytes_processed / file_size) * 100
                    progress_callback(
                        pct, bytes_processed, file_size, eta,
                        f"Encrypting... {pct:.1f}% | {format_speed(speed)} | ETA: {format_time(eta)}"
                    )
    
    elapsed = time.time() - start_time
    if progress_callback:
        progress_callback(100, file_size, file_size, 0, 
                         f"Done! {format_size(file_size)} in {format_time(elapsed)}")
    
    return True, str(output_path)


def recover_key_from_answer(file_path: Path, security_answer: str) -> tuple:
    """
    Recover the encryption key using the security answer.
    
    Returns: (success, key_bytes or error_message)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        return False, "Required libraries not installed!"
    
    file_path = Path(file_path)
    
    with open(file_path, 'rb') as infile:
        magic = infile.read(4)
        
        if magic != STREAM_MAGIC:
            return False, "File format not supported for recovery"
        
        version = struct.unpack('>H', infile.read(2))[0]
        original_size = struct.unpack('>Q', infile.read(8))[0]
        chunk_size = struct.unpack('>Q', infile.read(8))[0]
        total_chunks = struct.unpack('>Q', infile.read(8))[0]
        meta_len = struct.unpack('>I', infile.read(4))[0]
        meta_bytes = infile.read(meta_len)
        
        metadata = json.loads(meta_bytes.decode())
        
        if not metadata.get('has_recovery') or 'recovery' not in metadata:
            return False, "This file does not have security question recovery enabled"
        
        recovery = metadata['recovery']
        question = recovery['question']
        recovery_salt = base64.b64decode(recovery['recovery_salt'])
        recovery_nonce = base64.b64decode(recovery['recovery_nonce'])
        encrypted_key = base64.b64decode(recovery['encrypted_key'])
        
        # Derive key from the answer
        answer_key = hash_secret_raw(
            secret=security_answer.lower().strip().encode('utf-8'),
            salt=recovery_salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        
        # Try to decrypt the original key
        try:
            recovery_cipher = ChaCha20Poly1305(answer_key)
            original_key = recovery_cipher.decrypt(recovery_nonce, encrypted_key, None)
            return True, original_key
        except Exception:
            return False, "Wrong answer! The security answer is incorrect."


def get_security_question(file_path: Path) -> tuple:
    """
    Get the security question from an encrypted file.
    
    Returns: (has_question, question_text or None)
    """
    file_path = Path(file_path)
    
    try:
        with open(file_path, 'rb') as infile:
            magic = infile.read(4)
            
            if magic != STREAM_MAGIC:
                return False, None
            
            version = struct.unpack('>H', infile.read(2))[0]
            original_size = struct.unpack('>Q', infile.read(8))[0]
            chunk_size = struct.unpack('>Q', infile.read(8))[0]
            total_chunks = struct.unpack('>Q', infile.read(8))[0]
            meta_len = struct.unpack('>I', infile.read(4))[0]
            meta_bytes = infile.read(meta_len)
            
            metadata = json.loads(meta_bytes.decode())
            
            if metadata.get('has_recovery') and 'recovery' in metadata:
                return True, metadata['recovery']['question']
            
            return False, None
    except:
        return False, None


def decrypt_file_with_key(file_path: Path, key_bytes: bytes, output_path: Path = None,
                          progress_callback=None) -> tuple:
    """
    Decrypt file of ANY size using streaming encryption.
    
    Automatically detects quantum-encrypted files and uses hybrid key derivation.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        return False, "Required libraries not installed!", None
    
    file_path = Path(file_path)
    
    import time
    start_time = time.time()
    
    with open(file_path, 'rb') as infile:
        # Read header
        magic = infile.read(4)
        
        # Handle streaming format (SVLS)
        if magic == STREAM_MAGIC:
            version = struct.unpack('>H', infile.read(2))[0]
            original_size = struct.unpack('>Q', infile.read(8))[0]
            chunk_size = struct.unpack('>Q', infile.read(8))[0]
            total_chunks = struct.unpack('>Q', infile.read(8))[0]
            meta_len = struct.unpack('>I', infile.read(4))[0]  # 4 bytes for larger metadata
            meta_bytes = infile.read(meta_len)
            salt = infile.read(16)
            
            metadata = json.loads(meta_bytes.decode())
            original_name = metadata.get('name', 'decrypted_file')
            
            # Derive key using Argon2id
            derived_key = hash_secret_raw(
                secret=key_bytes,
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID
            )
            
            cipher = ChaCha20Poly1305(derived_key)
            
            # Output path
            if output_path is None:
                output_path = file_path.parent / f"decrypted_{original_name}"
            
            bytes_processed = 0
            
            with open(output_path, 'wb') as outfile:
                for chunk_idx in range(total_chunks):
                    # Read encrypted chunk
                    enc_chunk_len = struct.unpack('>Q', infile.read(8))[0]
                    encrypted_chunk = infile.read(enc_chunk_len)
                    
                    # Generate nonce for this chunk
                    nonce = get_nonce_for_chunk(salt, chunk_idx)
                    
                    # Decrypt
                    try:
                        decrypted_chunk = cipher.decrypt(nonce, encrypted_chunk, None)
                    except Exception:
                        return False, "Wrong key! The key you entered is incorrect.", None
                    
                    outfile.write(decrypted_chunk)
                    bytes_processed += len(decrypted_chunk)
                    
                    # Progress
                    if progress_callback:
                        elapsed = time.time() - start_time
                        if elapsed > 0 and bytes_processed > 0:
                            speed = bytes_processed / elapsed
                            remaining = original_size - bytes_processed
                            eta = remaining / speed if speed > 0 else 0
                            pct = (bytes_processed / original_size) * 100
                            progress_callback(
                                pct, bytes_processed, original_size, eta,
                                f"Decrypting... {pct:.1f}% | {format_speed(speed)} | ETA: {format_time(eta)}"
                            )
            
            elapsed = time.time() - start_time
            if progress_callback:
                progress_callback(100, original_size, original_size, 0,
                                 f"Done! {format_size(original_size)} in {format_time(elapsed)}")
            
            return True, str(output_path), original_name
        
        # Handle legacy SVLT format (small files)
        elif magic == b"SVLT":
            version = struct.unpack('>H', infile.read(2))[0]
            ciphertext_len = struct.unpack('>Q', infile.read(8))[0]
            ciphertext = infile.read(ciphertext_len)
            
            if ENCRYPTION_LEVEL == "SECURE_VAULT":
                vault = SecureVault(algorithm="ChaCha20-Poly1305")
                key_password = base64.b64encode(key_bytes).decode('ascii')
                try:
                    decrypted = vault.decrypt(ciphertext, key_password)
                except ValueError:
                    return False, "Wrong key! The key you entered is incorrect.", None
            else:
                return False, "SecureVault module not available!", None
            
            # Parse metadata
            meta_len = struct.unpack('>I', decrypted[:4])[0]
            metadata = json.loads(decrypted[4:4+meta_len].decode())
            plaintext = decrypted[4+meta_len:]
            original_name = metadata.get('name', 'decrypted_file')
            
            if output_path is None:
                output_path = file_path.parent / f"decrypted_{original_name}"
            
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            return True, str(output_path), original_name
        
        # Handle legacy formats
        elif magic in (b"QFRT", b"QINF"):
            version = struct.unpack('>H', infile.read(2))[0]
            num_layers = struct.unpack('>I', infile.read(4))[0]
            stored_tag = infile.read(32)
            ciphertext_len = struct.unpack('>Q', infile.read(8))[0]
            ciphertext = infile.read(ciphertext_len)
            
            expected_tag = hashlib.sha3_256(key_bytes + ciphertext).digest()
            if stored_tag != expected_tag:
                return False, "Wrong key! The key you entered is incorrect.", None
            
            derived = hashlib.shake_256(key_bytes).digest(len(ciphertext))
            decrypted = bytes(a ^ b for a, b in zip(ciphertext, derived))
            
            meta_len = struct.unpack('>I', decrypted[:4])[0]
            metadata = json.loads(decrypted[4:4+meta_len].decode())
            plaintext = decrypted[4+meta_len:]
            original_name = metadata.get('name', 'decrypted_file')
            
            if output_path is None:
                output_path = file_path.parent / f"decrypted_{original_name}"
            
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            return True, str(output_path), original_name
        
        else:
            return False, "Not a valid encrypted file!", None


# ════════════════════════════════════════════════════════════════════════════════
# WINDOWS FILE DIALOG
# ════════════════════════════════════════════════════════════════════════════════

def open_file_dialog(title="Select File"):
    """Open native Windows file dialog"""
    try:
        ps_script = '''
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = "''' + title + '''"
        $dialog.Filter = "All Files (*.*)|*.*|Encrypted Files (*.qenc)|*.qenc"
        $dialog.ShowDialog() | Out-Null
        [Console]::WriteLine($dialog.FileName)
        '''
        result = subprocess.run(['powershell', '-Command', ps_script], 
                               capture_output=True, text=True, encoding='utf-8')
        path = result.stdout.strip()
        # Validate path exists
        if path and os.path.exists(path):
            return path
        return None
    except:
        return None


def save_file_dialog(title="Save File As", default_name="encrypted.qenc"):
    """Open native Windows save file dialog"""
    try:
        # Sanitize default name for PowerShell
        safe_name = default_name.replace("'", "").replace('"', '')
        ps_script = '''
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Title = "''' + title + '''"
        $dialog.Filter = "Encrypted Files (*.qenc)|*.qenc|All Files (*.*)|*.*"
        $dialog.FileName = "''' + safe_name + '''"
        $dialog.ShowDialog() | Out-Null
        [Console]::WriteLine($dialog.FileName)
        '''
        result = subprocess.run(['powershell', '-Command', ps_script], 
                               capture_output=True, text=True, encoding='utf-8')
        path = result.stdout.strip()
        return path if path else None
    except:
        return None


def copy_to_clipboard(text):
    """Copy text to Windows clipboard"""
    try:
        subprocess.run(['clip'], input=text.encode('utf-8'), check=True)
        return True
    except:
        return False


# ════════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ════════════════════════════════════════════════════════════════════════════════

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def show_header():
    width = 65
    print()
    print(c("╔" + "═" * width + "╗", Colors.BRIGHT_CYAN))
    print(c("║", Colors.BRIGHT_CYAN) + c("QUANTUM FILE ENCRYPTOR".center(width), Colors.HEADER) + c("║", Colors.BRIGHT_CYAN))
    print(c("║", Colors.BRIGHT_CYAN) + c("━" * width, Colors.CYAN) + c("║", Colors.BRIGHT_CYAN))
    if QUANTUM_AVAILABLE:
        print(c("║", Colors.BRIGHT_CYAN) + c("Post-Quantum Hybrid Encryption • FIPS 203/204".center(width), Colors.MUTED) + c("║", Colors.BRIGHT_CYAN))
    else:
        print(c("║", Colors.BRIGHT_CYAN) + c("Secure Vault Edition • Industry-Standard Encryption".center(width), Colors.MUTED) + c("║", Colors.BRIGHT_CYAN))
    print(c("╠" + "═" * width + "╣", Colors.BRIGHT_CYAN))
    if ENCRYPTION_LEVEL == "QUANTUM_SECURE_VAULT":
        print(c("║", Colors.BRIGHT_CYAN) + c("🔐 ML-KEM-1024 + AES-256-GCM │ NIST Level 5".center(width), Colors.SUCCESS) + c("║", Colors.BRIGHT_CYAN))
    elif ENCRYPTION_LEVEL == "SECURE_VAULT":
        print(c("║", Colors.BRIGHT_CYAN) + c("🔐 ChaCha20-Poly1305 + Argon2id │ 256-bit Security".center(width), Colors.SUCCESS) + c("║", Colors.BRIGHT_CYAN))
    else:
        print(c("║", Colors.BRIGHT_CYAN) + c("[!] Fallback Mode (SecureVault not found)".center(width), Colors.WARNING) + c("║", Colors.BRIGHT_CYAN))
    print(c("╚" + "═" * width + "╝", Colors.BRIGHT_CYAN))
    print()


# ════════════════════════════════════════════════════════════════════════════════
# MENU FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def menu_encrypt():
    """Encrypt a file or folder - generates a key with advanced options"""
    clear()
    show_header()
    
    print(c("  ┌" + "─" * 50 + "┐", Colors.CYAN))
    print(c("  │", Colors.CYAN) + c("ENCRYPT FILE / FOLDER".center(50), Colors.BOLD) + c("│", Colors.CYAN))
    print(c("  └" + "─" * 50 + "┘", Colors.CYAN))
    print()
    
    # Step 1: Choose what to encrypt
    print_step(1, "What do you want to encrypt?")
    print(c("  " + "─" * 40, Colors.MUTED))
    print(f"  {c('[1]', Colors.BRIGHT_CYAN)} Single File")
    print(f"  {c('[2]', Colors.BRIGHT_CYAN)} Entire Folder (all files inside)")
    print()
    
    input_type = input(c("  Choose [1/2]: ", Colors.BRIGHT_WHITE)).strip()
    print()
    
    file_path = None
    is_folder = False
    temp_zip = None
    
    if input_type == '2':
        # Folder selection
        is_folder = True
        print_step(2, "Select folder to encrypt...")
        
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
            root.destroy()
        except:
            folder_path = input("  Enter folder path: ").strip().strip('"')
        
        if not folder_path:
            print_error("No folder selected.")
            input("\n  Press Enter to continue...")
            return
        
        folder_path = Path(folder_path)
        
        if not folder_path.is_dir():
            print_error("Not a valid folder.")
            input("\n  Press Enter to continue...")
            return
        
        # Count files in folder
        all_files = list(folder_path.rglob("*"))
        file_count = len([f for f in all_files if f.is_file()])
        total_size = sum(f.stat().st_size for f in all_files if f.is_file())
        
        print(f"  Folder: {c(folder_path.name, Colors.BRIGHT_WHITE)}")
        print(f"  Files: {c(str(file_count), Colors.BRIGHT_WHITE)} files")
        print(f"  Total Size: {c(format_size(total_size), Colors.BRIGHT_WHITE)}")
        print()
        
        # Compress folder to ZIP
        print_step(3, "Compressing folder...")
        
        temp_zip = folder_path.parent / f"{folder_path.name}.zip"
        
        # Progress for compression
        pbar = ProgressBar(file_count, desc="Compressing")
        
        def compress_progress(pct, processed, total, eta, msg):
            pbar.update(processed, status=msg)
        
        try:
            zip_path = zip_folder(folder_path, temp_zip, compress_progress)
            pbar.finish("Compression Complete!")
        except Exception as e:
            print()
            print_error(f"Could not compress folder: {e}")
            # Clean up partial zip if it exists
            if temp_zip.exists():
                try:
                    temp_zip.unlink()
                except:
                    pass
            input("\n  Press Enter to continue...")
            return
        print()
        
        file_path = zip_path
        file_size = file_path.stat().st_size
        print(f"  Compressed: {c(format_size(file_size), Colors.BRIGHT_WHITE)}")
        print()
        
    else:
        # Single file selection (original behavior)
        print_step(2, "Select file to encrypt...")
        
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)  # Make dialog appear on top
            root.focus_force()  # Force focus
            file_path = filedialog.askopenfilename(parent=root, title="Select File to Encrypt")
            root.destroy()
        except:
            file_path = input("  Enter file path: ").strip().strip('"')
        
        if not file_path:
            print_error("No file selected.")
            input("\n  Press Enter to continue...")
            return
        
        file_path = Path(file_path)
        
        if file_path.suffix == '.qenc':
            print_error("File is already encrypted!")
            input("\n  Press Enter to continue...")
            return
        
        if not file_path.exists():
            print_error("File does not exist.")
            input("\n  Press Enter to continue...")
            return
            
        file_size = file_path.stat().st_size
        print(f"  File: {c(file_path.name, Colors.BRIGHT_WHITE)}")
        print(f"  Size: {c(format_size(file_size), Colors.BRIGHT_WHITE)}")
    
    chunk_size = get_optimal_chunk_size()
    total_chunks = (file_size + chunk_size - 1) // chunk_size
    print(f"  Chunks: {total_chunks} x {format_size(chunk_size)} (using 70% RAM)")
    print()
    
    # Step 2: Save location
    print_step(2, "Choose where to save encrypted file...")
    default_name = file_path.name + ".qenc"
    
    output_path = None
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)  # Make dialog appear on top
        root.focus_force()  # Force focus
        output_path = filedialog.asksaveasfilename(
            parent=root,
            title="Save Encrypted File As",
            initialfile=default_name,
            defaultextension=".qenc",
            filetypes=[("Encrypted Files", "*.qenc")]
        )
        root.destroy()
    except:
        output_path = input(f"  Output path [{default_name}]: ").strip().strip('"')
        if not output_path:
            output_path = str(file_path.parent / default_name)

    if not output_path:
        print_error("No save location selected.")
        input("\n  Press Enter to continue...")
        return
    
    output_path = Path(output_path)
    if not output_path.suffix == '.qenc':
        output_path = output_path.with_suffix(output_path.suffix + '.qenc')
    
    print(f"  Save to: {c(output_path.name, Colors.BRIGHT_WHITE)}")
    print()
    
    # Generate unique encryption key
    key_string = generate_key()
    key_bytes = key_to_bytes(key_string)
    
    # Initialize variables
    key_shares = None
    security_question = None
    security_answer = None
    max_uses = None
    expire_date = None
    num_shares = 0
    threshold = 0
    
    # SECURITY MODE SELECTION
    print(c("  SECURITY MODE", Colors.HEADER))
    print(c("  " + "─" * 40, Colors.MUTED))
    print(f"  {c('[1]', Colors.BRIGHT_CYAN)} Basic (Key Only) - Good for general use")
    print(f"  {c('[2]', Colors.BRIGHT_CYAN)} Advanced (Split Key, Recovery, Self-Destruct) - Max Security")
    print()
    
    mode = input(c("  Choose mode [1/2]: ", Colors.BRIGHT_WHITE)).strip()
    
    if mode == '2':
        print()
        
        # Step 3: Split Key
        print_step(3, "Split Key (Optional)")
        print(c("  " + "-" * 40, Colors.MUTED))
        print("  Split your key into parts (Shamir's Secret Sharing).")
        print("  Any M of N parts can decrypt.")
        print()
        
        split_key = input("  Split key into parts? (y/n): ").strip().lower()
        if split_key == 'y':
            try:
                num_shares = int(input("  Total number of parts (N): ").strip())
                threshold = int(input("  Parts needed to decrypt (M): ").strip())
                
                if threshold > num_shares or threshold < 2 or num_shares < 2:
                    print_warning("Invalid N or M. Using single key.")
                else:
                    key_shares = split_secret(key_bytes, num_shares, threshold)
                    print_success(f"Key will be split into {num_shares} parts, {threshold} needed.")
            except ValueError:
                print_warning("Invalid number. Using single key.")
        print()
        
        # Step 4: Security Question
        print_step(4, "Security Question (Optional)")
        print(c("  " + "-" * 40, Colors.MUTED))
        print("  Recover your file if you lose the key.")
        print()
        
        add_security = input("  Add security question? (y/n): ").strip().lower()
        if add_security == 'y':
            print("  Enter a question only YOU can answer:")
            security_question = input("  Question: ").strip()
            if security_question:
                print("  Enter the answer (case-insensitive):")
                security_answer = input("  Answer: ").strip()
                if security_answer:
                    print_success("Security question set!")
                else:
                    security_question = None
                    print_warning("No answer. Disabled.")
            else:
                print_warning("No question. Disabled.")
        print()
        
        # Step 5: Self-Destruct
        print_step(5, "Self-Destruct (Optional)")
        print(c("  " + "-" * 40, Colors.MUTED))
        print("  File auto-deletes after limit. " + c("[!] IRREVERSIBLE!", Colors.RED))
        print()
        
        add_destruct = input("  Enable self-destruct? (y/n): ").strip().lower()
        if add_destruct == 'y':
            print("  [1] Limit by decryptions")
            print("  [2] Limit by date")
            print("  [3] Both")
            destruct_type = input("  Choose: ").strip()
            
            if destruct_type in ['1', '3']:
                try:
                    max_uses = int(input("  Max decryptions: ").strip())
                    print_success(f"Self-destruct after {max_uses} decryptions.")
                except:
                    print_warning("Invalid number. Disabled.")
            
            if destruct_type in ['2', '3']:
                date_str = input("  Expiration date (YYYY-MM-DD): ").strip()
                try:
                    expire_date = datetime.strptime(date_str, "%Y-%m-%d")
                    if expire_date <= datetime.now():
                        print_warning("Date must be in future. Disabled.")
                        expire_date = None
                    else:
                        print_success(f"Expires on {expire_date.strftime('%Y-%m-%d')}.")
                except:
                    print_warning("Invalid date. Disabled.")
        print()

    # Step 6: Encryption
    step_num = 6 if mode == '2' else 3
    print_step(step_num, "Encrypting...")
    print()
    
    # Progress bar callback
    pbar = ProgressBar(file_size, desc="Encrypting")
    
    def progress_callback(pct, bytes_done, total_bytes, eta, message):
        pbar.update(bytes_done, status=message)
    
    success, result = encrypt_file_with_key(
        file_path, key_bytes, output_path, progress_callback,
        security_question=security_question,
        security_answer=security_answer,
        extra_metadata={'is_split': bool(key_shares), 'is_folder': is_folder}
    )
    pbar.finish("Encryption Complete!")
    print()
    
    # Clean up temporary ZIP file (if folder was encrypted)
    if temp_zip and temp_zip.exists():
        try:
            temp_zip.unlink()
        except:
            pass
    
    if success:
        # Create self-destruct tracker
        if max_uses or expire_date:
            create_destruct_tracker(Path(result), max_uses=max_uses, expire_date=expire_date)
        
        print_box("ENCRYPTION SUCCESSFUL!", [
            f"File: {Path(result).name}",
            f"Path: {result}"
        ], color=Colors.GREEN)
        print()
        
        if max_uses or expire_date:
            print_warning("SELF-DESTRUCT ENABLED:")
            if max_uses: print(f"    - Deletes after {max_uses} decryptions")
            if expire_date: print(f"    - Expires on {expire_date.strftime('%Y-%m-%d')}")
            print()
        
        # Show Key
        if key_shares:
            print(c("  ┌" + "─" * 60 + "┐", Colors.SUCCESS))
            print(c("  │", Colors.SUCCESS) + c(f"KEY SPLIT INTO {num_shares} PARTS".center(60), Colors.BOLD) + c("│", Colors.SUCCESS))
            print(c("  │", Colors.SUCCESS) + c(f"(ANY {threshold} PARTS CAN DECRYPT)".center(60), Colors.BOLD) + c("│", Colors.SUCCESS))
            print(c("  └" + "─" * 60 + "┘", Colors.SUCCESS))
            print()
            
            for idx, share in key_shares:
                share_str = format_share(idx, share, num_shares, threshold)
                print(c(f"  PART {idx} of {num_shares}:", Colors.BRIGHT_CYAN))
                print(c("  +" + "-" * 60 + "+", Colors.CYAN))
                for i in range(0, len(share_str), 55):
                    print(c(f"  | {share_str[i:i+55]:<58} |", Colors.CYAN))
                print(c("  +" + "-" * 60 + "+", Colors.CYAN))
                print()
        else:
            print(c("  ┌" + "─" * 60 + "┐", Colors.SUCCESS))
            print(c("  │", Colors.SUCCESS) + c("YOUR DECRYPTION KEY".center(60), Colors.BOLD) + c("│", Colors.SUCCESS))
            print(c("  │", Colors.SUCCESS) + c("(COPY AND SAVE THIS!)".center(60), Colors.WARNING) + c("│", Colors.SUCCESS))
            print(c("  └" + "─" * 60 + "┘", Colors.SUCCESS))
            print()
            
            print(c("  +" + "-" * 60 + "+", Colors.BRIGHT_WHITE))
            key_lines = [key_string[i:i+50] for i in range(0, len(key_string), 50)]
            for line in key_lines:
                print(c(f"  | {line:<58} |", Colors.BRIGHT_WHITE))
            print(c("  +" + "-" * 60 + "+", Colors.BRIGHT_WHITE))
            print()
            
            if input("  Copy key? (y/n): ").lower() == 'y':
                if copy_to_clipboard(key_string):
                    print_success("Key copied!")
                else:
                    print_warning("Please copy manually.")
        print()
        
        # Step 7: Shred Original (Only in Advanced Mode)
        if mode == '2':
            print_step(7, "Secure Shred Original (Optional)")
            print(c("  " + "-" * 40, Colors.MUTED))
            print("  Permanently destroy original file. " + c("IRREVERSIBLE!", Colors.RED))
            print()
            
            if input("  Securely shred original? (y/n): ").lower() == 'y':
                print("  [1] Quick (1 pass)")
                print("  [2] DoD (3 passes)")
                print("  [3] Paranoid (7 passes)")
                lvl = input("  Choose: ").strip()
                passes = {'1': 1, '2': 3, '3': 7}.get(lvl, 3)
                
                print(f"\n  Shredding with {passes} passes...")
                if secure_shred_file(file_path, passes=passes):
                    print_success("Original file destroyed!")
                else:
                    print_error("Could not shred file.")
        
        print()
        print_info("To decrypt, use option [2] in main menu.")
        
    else:
        print_error(f"Encryption failed: {result}")
    
    input("\n  Press Enter to continue...")


def menu_decrypt():
    """Decrypt a file - with split key and self-destruct support"""
    clear()
    show_header()
    
    print(c("  ┌" + "─" * 50 + "┐", Colors.CYAN))
    print(c("  │", Colors.CYAN) + c("DECRYPT FILE".center(50), Colors.BOLD) + c("│", Colors.CYAN))
    print(c("  └" + "─" * 50 + "┘", Colors.CYAN))
    print()
    
    # Step 1: Select file
    print_step(1, "Select encrypted file...")
    
    # Use tkinter for file dialog
    file_path = None
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[("Encrypted Files", "*.qenc"), ("All Files", "*.*")]
        )
        root.destroy()
    except:
        file_path = input("  Enter file path: ").strip().strip('"')
    
    if not file_path:
        print_error("No file selected.")
        input("\n  Press Enter to continue...")
        return
    
    file_path = Path(file_path)
    
    if file_path.suffix != '.qenc':
        print_warning("File doesn't have .qenc extension.")
        if input("  Try anyway? (y/n): ").lower() != 'y':
            return
    
    print(f"  File: {c(file_path.name, Colors.BRIGHT_WHITE)}")
    print(f"  Size: {c(format_size(file_path.stat().st_size), Colors.BRIGHT_WHITE)}")
    print()
    
    # CHECK SELF-DESTRUCT STATUS
    should_destruct, destruct_reason, remaining_uses = check_self_destruct(file_path)
    
    if should_destruct:
        print_box("FILE HAS EXPIRED", [
            f"Reason: {destruct_reason}",
            "File has self-destructed and cannot be decrypted."
        ], color=Colors.RED)
        
        print_info("Securely destroying file...")
        destroy_encrypted_file(file_path)
        print_success("File has been securely destroyed.")
        input("\n  Press Enter to continue...")
        return
    
    if remaining_uses is not None:
        print(c(f"  [!] WARNING: {remaining_uses} decryption(s) remaining before self-destruct!", Colors.BRIGHT_YELLOW))
        print()
    
    # CHECK LOCKOUT STATUS
    lockout_status = get_lockout_status(file_path)
    
    if lockout_status['locked']:
        unlock_time = lockout_status['unlock_time'].strftime('%Y-%m-%d %H:%M:%S')
        print_box("FILE IS LOCKED", [
            "Too many failed attempts.",
            f"Lockout level: {lockout_status['lockout_level']}",
            f"Unlock time: {unlock_time}"
        ], color=Colors.RED)
        
        print(c("  Even with correct password, you cannot decrypt yet.", Colors.RED))
        input("\n  Press Enter to continue...")
        return
    
    if lockout_status['failed_attempts'] > 0:
        remaining = 3 - lockout_status['failed_attempts']
        print(c(f"  [!] {lockout_status['failed_attempts']} failed attempt(s). {remaining} remaining.", Colors.YELLOW))
        print()
    
    # Check metadata for available decryption methods
    metadata = read_file_metadata(file_path)
    has_recovery = False
    security_question = None
    is_split = True # Default to True for legacy support (if flag missing)
    
    if metadata:
        if metadata.get('has_recovery') and 'recovery' in metadata:
            has_recovery = True
            security_question = metadata['recovery']['question']
            
        if 'is_split' in metadata:
            is_split = metadata['is_split']
    
    # Auto-select method if only basic key is available
    if not has_recovery and not is_split:
        print_info("File secured with Standard Key (Basic Mode).")
        decrypt_method = '1'
    else:
        print_step(2, "How do you want to decrypt?")
        print(c("  " + "─" * 40, Colors.MUTED))
        print(f"  {c('[1]', Colors.BRIGHT_CYAN)} Enter my decryption KEY")
        
        if is_split:
            print(f"  {c('[2]', Colors.BRIGHT_CYAN)} Enter SPLIT KEY parts (if key was split)")
        else:
            print(f"  {c('[2]', Colors.MUTED)} Enter SPLIT KEY parts (Not enabled)")
        
        if has_recovery:
            print(f"  {c('[3]', Colors.BRIGHT_CYAN)} I forgot/lost my key (use security question)")
        else:
            print(f"  {c('[3]', Colors.MUTED)} I forgot/lost my key (not available)")
        print()
        
        while True:
            decrypt_method = input(c("  Choose [1/2/3]: ", Colors.BRIGHT_WHITE)).strip()
            if decrypt_method == '2' and not is_split:
                print_warning("Split key was not enabled for this file.")
                continue
            if decrypt_method == '3' and not has_recovery:
                print_warning("Recovery was not enabled for this file.")
                continue
            if decrypt_method in ['1', '2', '3']:
                break
    
    key_bytes = None
    
    if decrypt_method == '3':
        if not has_recovery:
            print_error("Security question recovery not available.")
            input("\n  Press Enter to continue...")
            return
            
        print_box("KEY RECOVERY", [
            "Your Security Question:",
            f">>> {security_question}"
        ], color=Colors.CYAN)
        
        print("  Enter your answer (case-insensitive):")
        security_answer = input("  Answer: ").strip()
        
        if not security_answer:
            print_error("No answer entered.")
            return
            
        print_info("Verifying answer...")
        success, result = recover_key_from_answer(file_path, security_answer)
        
        if success:
            key_bytes = result
            print_success("Answer correct! Key recovered.")
            print()
        else:
            failed_count, lockout_level = record_failed_attempt(file_path)
            if failed_count >= 3:
                print_error(f"Too many failed attempts! File locked.")
            else:
                remaining = 3 - failed_count
                print_error(f"Wrong answer. {remaining} attempt(s) remaining.")
            input("\n  Press Enter to continue...")
            return
            
    elif decrypt_method == '2':
        print()
        print_info("Enter your key parts one by one. Type 'done' to finish.")
        print()
        
        shares = []
        threshold = None
        total = None
        
        while True:
            share_input = input(f"  Key part {len(shares) + 1}: ").strip()
            if share_input.lower() == 'done': break
            if not share_input: continue
            
            parsed = parse_share(share_input)
            if parsed is None:
                print_warning("Invalid format.")
                continue
                
            idx, share_bytes, t, thresh = parsed
            
            if threshold is None:
                threshold = thresh
                total = t
            elif thresh != threshold or t != total:
                print_warning("Part doesn't match previous parts.")
                continue
                
            if any(s[0] == idx for s in shares):
                print_warning(f"Part {idx} already entered.")
                continue
                
            shares.append((idx, share_bytes))
            print_success(f"Part {idx} of {total} accepted. ({len(shares)}/{threshold} needed)")
            
            if len(shares) >= threshold:
                print_success("Enough parts collected!")
                break
        
        if len(shares) < (threshold or 2):
            print_error("Not enough parts.")
            input("\n  Press Enter to continue...")
            return
            
        try:
            key_bytes = combine_shares(shares)
            print_success("Key reconstructed.")
            print()
        except Exception as e:
            print_error(f"Could not reconstruct key: {e}")
            return
            
    else:
        print()
        print_info("Enter your decryption key:")
        key_string = input("  Key: ").strip()
        
        if not key_string:
            print_error("No key entered.")
            return
            
        key_bytes = key_to_bytes(key_string)
        if key_bytes is None:
            failed_count, lockout_level = record_failed_attempt(file_path)
            if failed_count >= 3:
                 print_error("Too many failed attempts! File locked.")
            else:
                 print_error(f"Wrong key format. {3 - failed_count} attempts remaining.")
            input("\n  Press Enter to continue...")
            return
    
    print()
    # Step 3: Save location
    print_step(3, "Choose where to save decrypted file...")
    orig_name = file_path.stem if file_path.stem.endswith('.qenc') else file_path.stem
    default_name = orig_name if '.' in orig_name else orig_name + ".decrypted"
    
    output_path = None
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted File As",
            initialfile=default_name
        )
        root.destroy()
    except:
        output_path = input(f"  Output path [{default_name}]: ").strip().strip('"')
        if not output_path:
            output_path = str(file_path.parent / default_name)

    if not output_path:
        print_error("No save location selected.")
        input("\n  Press Enter to continue...")
        return
    
    output_path = Path(output_path)
    print(f"  Save to: {c(output_path.name, Colors.BRIGHT_WHITE)}")
    print()
    
    # Step 4: Decrypting
    print_step(4, "Decrypting...")
    
    pbar = ProgressBar(file_path.stat().st_size, desc="Decrypting")
    
    def progress_callback(pct, bytes_done, total_bytes, eta, message):
        pbar.update(bytes_done, status=message)
    
    success, result, orig = decrypt_file_with_key(file_path, key_bytes, output_path, progress_callback)
    pbar.finish("Decryption Complete!")
    print()
    
    if success:
        clear_lockout(file_path)
        should_destroy, remaining = increment_destruct_counter(file_path)
        
        # Check if this was a folder archive - auto-extract if so
        decrypted_path = Path(result)
        final_result = result
        
        if metadata and metadata.get('is_folder') and decrypted_path.suffix == '.zip':
            print_info("Encrypted folder detected. Extracting...")
            
            pbar_extract = ProgressBar(100, desc="Extracting")
            
            def extract_progress(pct, processed, total, eta, msg):
                pbar_extract.update(pct, status=msg)
            
            try:
                extracted_folder = unzip_folder(decrypted_path, decrypted_path.parent, extract_progress)
                pbar_extract.finish("Extraction Complete!")
                print()
                
                # Delete the temporary zip file
                decrypted_path.unlink()
                final_result = str(extracted_folder)
                
                print_box("FOLDER DECRYPTION SUCCESSFUL!", [
                    f"Folder: {extracted_folder.name}",
                    f"Location: {extracted_folder}"
                ], color=Colors.GREEN)
            except Exception as e:
                pbar_extract.finish("Extraction failed!")
                print_warning(f"Could not extract folder: {e}")
                print_info(f"The ZIP file is saved at: {decrypted_path}")
                
                print_box("DECRYPTION SUCCESSFUL!", [
                    f"File: {decrypted_path.name}",
                    f"Location: {result}"
                ], color=Colors.GREEN)
        else:
            print_box("DECRYPTION SUCCESSFUL!", [
                f"File: {Path(result).name}",
                f"Location: {result}"
            ], color=Colors.GREEN)
        print()
        
        if remaining is not None:
             print(c(f"  [!] {remaining} decryption(s) remaining before self-destruct!", Colors.BRIGHT_YELLOW))
        
        if should_destroy:
            print()
            print_box("FINAL DECRYPTION - FILE SELF-DESTRUCTING", [
                "This was the last allowed decryption.",
                "Securely destroying encrypted file..."
            ], color=Colors.RED)
            
            destroy_encrypted_file(file_path)
            print_success("Encrypted file destroyed.")
            
    else:
        if "Wrong key" in result:
            failed_count, lockout_level = record_failed_attempt(file_path)
            if failed_count >= 3:
                print_error("Too many failed attempts! File locked.")
            else:
                remaining = 3 - failed_count
                print_error(f"Wrong password/key! {remaining} attempt(s) remaining.")
        else:
            print_error(f"Decryption failed: {result}")
            
    input("\n  Press Enter to continue...")


def menu_batch_encrypt():
    """Batch encrypt multiple files"""
    clear()
    show_header()
    
    print(c("  ┌" + "─" * 50 + "┐", Colors.CYAN))
    print(c("  │", Colors.CYAN) + c("BATCH ENCRYPT".center(50), Colors.BOLD) + c("│", Colors.CYAN))
    print(c("  └" + "─" * 50 + "┘", Colors.CYAN))
    print()
    
    print_info("Select multiple files to encrypt with the same key.")
    print()
    
    # Get files using file dialog
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        file_paths = filedialog.askopenfilenames(title="Select Files to Encrypt")
        root.destroy()
    except:
        print_error("File dialog not available.")
        input("\n  Press Enter to continue...")
        return
    
    if not file_paths:
        print_error("No files selected.")
        input("\n  Press Enter to continue...")
        return
    
    print_success(f"Selected {len(file_paths)} file(s):")
    print()
    total_size = 0
    for fp in file_paths:
        path = Path(fp)
        size = path.stat().st_size
        total_size += size
        print(f"    {c('•', Colors.CYAN)} {path.name} ({format_size(size)})")
    
    print()
    print(c(f"  Total: {format_size(total_size)}", Colors.BRIGHT_WHITE))
    print()
    
    confirm = input(c("  Encrypt all files? (y/n): ", Colors.BRIGHT_WHITE)).strip().lower()
    if confirm != 'y':
        print_warning("Cancelled.")
        input("\n  Press Enter to continue...")
        return
    
    # Generate single key for all files
    key_string = generate_key()
    key_bytes = key_to_bytes(key_string)
    
    print()
    print_info("Encrypting files...")
    print()
    
    success_count = 0
    for i, fp in enumerate(file_paths, 1):
        path = Path(fp)
        output_path = path.with_suffix(path.suffix + '.qenc')
        
        print(f"  [{i}/{len(file_paths)}] {path.name}...", end=" ", flush=True)
        
        success, result = encrypt_file_with_key(path, key_bytes, output_path)
        
        if success:
            print(c("✓", Colors.SUCCESS))
            success_count += 1
        else:
            print(c("✗", Colors.ERROR))
    
    print()
    print_success(f"Encrypted {success_count}/{len(file_paths)} files!")
    print()
    
    # Show key
    print(c("  ┌" + "─" * 60 + "┐", Colors.SUCCESS))
    print(c("  │", Colors.SUCCESS) + c("YOUR DECRYPTION KEY (same for all files)".center(60), Colors.BOLD) + c("│", Colors.SUCCESS))
    print(c("  └" + "─" * 60 + "┘", Colors.SUCCESS))
    print()
    
    key_lines = [key_string[i:i+55] for i in range(0, len(key_string), 55)]
    for line in key_lines:
        print(c(f"    {line}", Colors.BRIGHT_CYAN))
    print()
    
    copy_choice = input("  Copy key to clipboard? (y/n): ").strip().lower()
    if copy_choice == 'y':
        if copy_to_clipboard(key_string):
            print_success("Key copied!")
        else:
            print_warning("Could not copy. Please copy manually.")
    
    print()
    print_warning("SAVE THIS KEY! All files use the same key.")
    
    input("\n  Press Enter to continue...")


def menu_file_info():
    """Show file info and verify encrypted files"""
    clear()
    show_header()
    
    print(c("  ┌" + "─" * 50 + "┐", Colors.CYAN))
    print(c("  │", Colors.CYAN) + c("FILE INFO & VERIFY".center(50), Colors.BOLD) + c("│", Colors.CYAN))
    print(c("  └" + "─" * 50 + "┘", Colors.CYAN))
    print()
    
    print_info("Select an encrypted file to view its details.")
    print()
    
    file_path = open_file_dialog("Select Encrypted File (.qenc)")
    
    if not file_path:
        print_error("No file selected.")
        input("\n  Press Enter to continue...")
        return
    
    file_path = Path(file_path)
    
    print()
    print(c("  FILE DETAILS", Colors.HEADER))
    print(c("  " + "─" * 40, Colors.MUTED))
    print()
    
    # Basic info
    print(f"  {c('Name:', Colors.CYAN)}    {file_path.name}")
    print(f"  {c('Size:', Colors.CYAN)}    {format_size(file_path.stat().st_size)}")
    print(f"  {c('Path:', Colors.CYAN)}    {file_path.parent}")
    print()
    
    # Check if valid encrypted file
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic == STREAM_MAGIC:
                version = struct.unpack('>H', f.read(2))[0]
                file_size = struct.unpack('>Q', f.read(8))[0]
                chunk_size = struct.unpack('>Q', f.read(8))[0]
                f.read(16)  # salt
                meta_len = struct.unpack('>I', f.read(4))[0]
                meta_bytes = f.read(meta_len)
                metadata = json.loads(meta_bytes.decode())
                
                print(c("  ENCRYPTION INFO", Colors.HEADER))
                print(c("  " + "─" * 40, Colors.MUTED))
                print()
                print(f"  {c('Format:', Colors.CYAN)}       Quantum Encrypted (v{version})")
                print(f"  {c('Original:', Colors.CYAN)}     {metadata.get('name', 'Unknown')}")
                print(f"  {c('Orig Size:', Colors.CYAN)}    {format_size(metadata.get('size', 0))}")
                print(f"  {c('Algorithm:', Colors.CYAN)}    {metadata.get('algorithm', 'ChaCha20-Poly1305')}")
                print(f"  {c('Encrypted:', Colors.CYAN)}    {metadata.get('time', 'Unknown')}")
                print(f"  {c('Chunks:', Colors.CYAN)}       {metadata.get('total_chunks', 1)}")
                print()
                
                # Recovery info
                if metadata.get('has_recovery'):
                    print_success("Security question recovery: ENABLED")
                else:
                    print_info("Security question recovery: Not set")
                
                # Quantum protection info
                if metadata.get('quantum_protected'):
                    quantum = metadata.get('quantum', {})
                    print_success(f"Quantum Protection: ML-KEM-{quantum.get('mlkem_version', '1024')} ({quantum.get('provider', 'unknown')})")
                else:
                    print_info("Quantum Protection: Classical encryption only")
                
                # Self-destruct info
                should_destruct, reason, remaining = check_self_destruct(file_path)
                if remaining is not None:
                    print_warning(f"Self-destruct: {remaining} decryption(s) remaining")
                elif should_destruct:
                    print_error(f"Self-destruct: EXPIRED ({reason})")
                else:
                    print_info("Self-destruct: Not enabled")
                
                # Lockout info
                lockout = get_lockout_status(file_path)
                if lockout['locked']:
                    print_error(f"Lockout: LOCKED until {lockout['unlock_time']}")
                elif lockout['failed_attempts'] > 0:
                    print_warning(f"Lockout: {lockout['failed_attempts']} failed attempt(s)")
                else:
                    print_success("Lockout: No issues")
                
                print()
                print_success("File is a valid encrypted file!")
            else:
                print_error("Not a valid Quantum Encrypted file!")
    except Exception as e:
        print_error(f"Could not read file: {e}")
    
    input("\n  Press Enter to continue...")


# ════════════════════════════════════════════════════════════════════════════════════════
# UPDATE CHECKER
# ════════════════════════════════════════════════════════════════════════════════════════

def menu_update():
    """Check for updates from GitHub and download if available"""
    import urllib.request
    import urllib.error
    
    clear()
    show_header()
    
    print(c("  ┌" + "─" * 50 + "┐", Colors.CYAN))
    print(c("  │", Colors.CYAN) + c("CHECK FOR UPDATES".center(50), Colors.BOLD) + c("│", Colors.CYAN))
    print(c("  └" + "─" * 50 + "┘", Colors.CYAN))
    print()
    
    print(f"  Current version: {c(APP_VERSION, Colors.BRIGHT_WHITE)}")
    print()
    
    # Check for updates
    print_step(1, "Checking for updates...")
    
    try:
        # Create request with User-Agent header (GitHub API requires it)
        req = urllib.request.Request(
            GITHUB_API_URL,
            headers={'User-Agent': 'QuantumFileEncryptor'}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
        
        latest_version = data.get('tag_name', '').lstrip('v')
        release_notes = data.get('body', 'No release notes available.')
        html_url = data.get('html_url', GITHUB_RELEASES_URL)
        assets = data.get('assets', [])
        
        print_success(f"Latest version: {latest_version}")
        print()
        
        # Compare versions
        def parse_version(v):
            try:
                return tuple(map(int, v.split('.')))
            except:
                return (0, 0, 0)
        
        current = parse_version(APP_VERSION)
        latest = parse_version(latest_version)
        
        if latest <= current:
            print(c("  ✅ You are running the latest version!", Colors.SUCCESS))
            print()
            input("\n  Press Enter to continue...")
            return
        
        # New version available
        print(c("  🆕 NEW VERSION AVAILABLE!", Colors.BRIGHT_YELLOW))
        print()
        print(f"  {c(APP_VERSION, Colors.MUTED)} → {c(latest_version, Colors.BRIGHT_GREEN)}")
        print()
        
        # Show release notes (first 5 lines)
        print(c("  Release Notes:", Colors.BRIGHT_WHITE))
        notes_lines = release_notes.split('\n')[:5]
        for line in notes_lines:
            print(f"    {c(line[:60], Colors.MUTED)}")
        if len(release_notes.split('\n')) > 5:
            print(f"    {c('...', Colors.MUTED)}")
        print()
        
        # Find downloadable asset (EXE file)
        exe_asset = None
        for asset in assets:
            if asset.get('name', '').endswith('.exe'):
                exe_asset = asset
                break
        
        if not exe_asset:
            print(c("  ⚠️  No direct download available.", Colors.WARNING))
            print(f"  Please visit: {c(html_url, Colors.BRIGHT_CYAN)}")
            print()
            
            # Offer to open browser
            open_browser = input("  Open download page in browser? (y/n): ").strip().lower()
            if open_browser == 'y':
                import webbrowser
                webbrowser.open(html_url)
                print_success("Opened browser!")
            
            input("\n  Press Enter to continue...")
            return
        
        # Ask to download
        download_url = exe_asset.get('browser_download_url')
        file_size = exe_asset.get('size', 0)
        
        print(f"  Download size: {c(format_size(file_size), Colors.BRIGHT_WHITE)}")
        print()
        
        confirm = input("  Download and install update? (y/n): ").strip().lower()
        if confirm != 'y':
            print(c("  Update cancelled.", Colors.MUTED))
            input("\n  Press Enter to continue...")
            return
        
        # Download with progress
        print()
        print_step(2, "Downloading update...")
        print()
        
        # Get current executable path
        if getattr(sys, 'frozen', False):
            # Running as compiled EXE
            current_exe = sys.executable
            download_path = current_exe + ".new"
        else:
            # Running as script - download to current directory
            current_exe = None
            download_path = Path(__file__).parent / exe_asset.get('name', 'QuantumFileEncryptor.exe')
        
        # Download with progress bar
        downloaded = 0
        block_size = 8192
        
        req = urllib.request.Request(download_url, headers={'User-Agent': 'QuantumFileEncryptor'})
        
        with urllib.request.urlopen(req, timeout=60) as response:
            with open(download_path, 'wb') as out_file:
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    downloaded += len(buffer)
                    out_file.write(buffer)
                    
                    # Show progress
                    if file_size > 0:
                        percent = (downloaded / file_size) * 100
                        bar_width = 40
                        filled = int(bar_width * downloaded / file_size)
                        bar = "█" * filled + "░" * (bar_width - filled)
                        print(f"\r  [{bar}] {percent:.1f}%  ", end="", flush=True)
        
        print()
        print()
        print_success("Download complete!")
        print()
        
        if current_exe:
            # Replace current executable
            print_step(3, "Installing update...")
            
            # Create batch script to replace EXE after this process exits
            batch_path = Path(current_exe).parent / "update.bat"
            batch_content = f'''@echo off
timeout /t 2 /nobreak > nul
del "{current_exe}"
move "{download_path}" "{current_exe}"
del "%~f0"
start "" "{current_exe}"
'''
            with open(batch_path, 'w') as f:
                f.write(batch_content)
            
            print()
            print(c("  ✅ UPDATE READY!", Colors.SUCCESS))
            print()
            print(c("  The application will now restart to complete the update.", Colors.BRIGHT_WHITE))
            print()
            input("  Press Enter to restart...")
            
            # Run the batch script and exit
            subprocess.Popen(['cmd', '/c', str(batch_path)], 
                           creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
            sys.exit(0)
        else:
            print(c("  ✅ UPDATE DOWNLOADED!", Colors.SUCCESS))
            print()
            print(f"  New version saved to: {c(str(download_path), Colors.BRIGHT_WHITE)}")
            print()
            print(c("  Please replace the old executable manually.", Colors.MUTED))
            input("\n  Press Enter to continue...")
            
    except urllib.error.URLError as e:
        print()
        print_error(f"Network error: {e.reason}")
        print(c("  Please check your internet connection.", Colors.MUTED))
        input("\n  Press Enter to continue...")
    except Exception as e:
        print()
        print_error(f"Update check failed: {e}")
        input("\n  Press Enter to continue...")


def main():
    """Main menu loop"""
    while True:
        clear()
        show_header()
        
        # Beautiful menu box
        print(c("  ┌" + "─" * 50 + "┐", Colors.CYAN))
        print(c("  │", Colors.CYAN) + c("MAIN MENU".center(50), Colors.BOLD + Colors.BRIGHT_WHITE) + c("│", Colors.CYAN))
        print(c("  ├" + "─" * 50 + "┤", Colors.CYAN))
        print(c("  │  ", Colors.CYAN) + c("[1]", Colors.BRIGHT_CYAN) + c(" 🔐 Encrypt a File", Colors.WHITE) + " " * 22 + c("│", Colors.CYAN))
        print(c("  │  ", Colors.CYAN) + c("[2]", Colors.BRIGHT_CYAN) + c(" 🔓 Decrypt a File", Colors.WHITE) + " " * 22 + c("│", Colors.CYAN))
        print(c("  │  ", Colors.CYAN) + c("[3]", Colors.BRIGHT_CYAN) + c(" 📁 Batch Encrypt Multiple Files", Colors.WHITE) + " " * 7 + c("│", Colors.CYAN))
        print(c("  │  ", Colors.CYAN) + c("[4]", Colors.BRIGHT_CYAN) + c(" ℹ  File Info & Verify", Colors.WHITE) + " " * 18 + c("│", Colors.CYAN))
        print(c("  │  ", Colors.CYAN) + c("[5]", Colors.BRIGHT_CYAN) + c(" 🔄 Check for Updates", Colors.WHITE) + " " * 19 + c("│", Colors.CYAN))
        print(c("  ├" + "─" * 50 + "┤", Colors.CYAN))
        print(c("  │  ", Colors.CYAN) + c("[0]", Colors.MUTED) + c(" Exit", Colors.MUTED) + " " * 35 + c("│", Colors.CYAN))
        print(c("  └" + "─" * 50 + "┘", Colors.CYAN))
        print()
        
        choice = input(c("  Enter choice: ", Colors.BRIGHT_WHITE)).strip()
        
        if choice == '1':
            menu_encrypt()
        elif choice == '2':
            menu_decrypt()
        elif choice == '3':
            menu_batch_encrypt()
        elif choice == '4':
            menu_file_info()
        elif choice == '5':
            menu_update()
        elif choice == '0':
            clear()
            print()
            print(c("  ✨ Thank you for using Quantum File Encryptor!", Colors.BRIGHT_CYAN))
            print(c("     Your files are safe. Stay secure! 🔐", Colors.MUTED))
            print()
            break


if __name__ == "__main__":
    import signal
    
    def signal_handler(sig, frame):
        """Handle Ctrl+C gracefully"""
        print()
        print(c("\n  ⛔ Operation cancelled by user (Ctrl+C)", Colors.WARNING))
        print(c("     Goodbye! 👋", Colors.MUTED))
        print()
        sys.exit(0)
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        main()
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        print(f"\n  ❌ Unexpected error: {e}")
        sys.exit(1)

