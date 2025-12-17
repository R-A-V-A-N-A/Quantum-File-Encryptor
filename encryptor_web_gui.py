"""
Quantum File Encryptor - Futuristic Web GUI
============================================
A stunning Star Atlas-inspired interface using Eel.

Features:
    - Animated particle stars background
    - Glassmorphism cards with neon glows
    - Full encryption/decryption functionality
    - Split key, self-destruct, secure shred
"""

import eel
import os
import sys
from pathlib import Path
from tkinter import filedialog, Tk
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import encryption functions
try:
    from encryptor_app import (
        generate_key, key_to_bytes, bytes_to_key,
        encrypt_file_with_key, decrypt_file_with_key,
        split_secret, combine_shares, format_share, parse_share,
        secure_shred_file, create_destruct_tracker,
        check_self_destruct, destroy_encrypted_file,
        get_security_question, recover_key_from_answer,
        get_lockout_status, record_failed_attempt, clear_lockout,
        increment_destruct_counter, format_size
    )
    print("[OK] Encryption functions loaded")
except ImportError as e:
    print(f"[ERROR] Could not import encryption functions: {e}")
    sys.exit(1)

# Initialize Eel
eel.init('web')

# Hide Tkinter root window
root = Tk()
root.withdraw()


@eel.expose
def select_encrypt_file():
    """Open file dialog and return file info"""
    file_path = filedialog.askopenfilename(
        title="Select File to Encrypt",
        filetypes=[("All Files", "*.*")]
    )
    
    if file_path:
        path = Path(file_path)
        size = path.stat().st_size
        return {
            'path': str(path),
            'name': path.name,
            'size': format_size(size)
        }
    return None


@eel.expose
def select_decrypt_file():
    """Open file dialog for encrypted files"""
    file_path = filedialog.askopenfilename(
        title="Select Encrypted File",
        filetypes=[("Encrypted Files", "*.qenc"), ("All Files", "*.*")]
    )
    
    if file_path:
        path = Path(file_path)
        size = path.stat().st_size
        
        # Check for security question
        has_q, question = get_security_question(path)
        
        return {
            'path': str(path),
            'name': path.name,
            'size': format_size(size),
            'hasQuestion': has_q,
            'question': question if has_q else None
        }
    return None


@eel.expose
def select_output_file(default_name):
    """Save file dialog"""
    file_path = filedialog.asksaveasfilename(
        title="Save As",
        initialfile=default_name,
        defaultextension=".qenc",
        filetypes=[("Encrypted Files", "*.qenc"), ("All Files", "*.*")]
    )
    return file_path if file_path else None


@eel.expose
def encrypt_file(file_path, options):
    """Encrypt a file with the given options"""
    try:
        if not file_path:
            return {'success': False, 'error': 'No file selected'}
        
        file_path = Path(file_path)
        
        # Generate output path
        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted File As",
            initialfile=file_path.name + ".qenc",
            defaultextension=".qenc",
            filetypes=[("Encrypted Files", "*.qenc")]
        )
        
        if not output_path:
            return {'success': False, 'error': 'No save location selected'}
        
        output_path = Path(output_path)
        
        # Generate key
        key_string = generate_key()
        key_bytes = key_to_bytes(key_string)
        
        # Get security question options
        security_question = None
        security_answer = None
        if options.get('securityQ'):
            security_question = options.get('question')
            security_answer = options.get('answer')
        
        # Progress callback
        def progress(pct, bytes_done, total_bytes, eta, message):
            eel.updateProgress('encrypt', int(pct), message)()
        
        # Encrypt
        success, result = encrypt_file_with_key(
            file_path, key_bytes, output_path, progress,
            security_question=security_question,
            security_answer=security_answer
        )
        
        if not success:
            return {'success': False, 'error': result}
        
        # Handle self-destruct
        if options.get('destruct'):
            try:
                max_uses = int(options.get('destructCount', 0))
                if max_uses > 0:
                    create_destruct_tracker(output_path, max_uses=max_uses)
            except:
                pass
        
        # Handle split key
        key_display = key_string
        if options.get('splitKey'):
            try:
                n = int(options.get('splitN', 5))
                m = int(options.get('splitM', 3))
                shares = split_secret(key_bytes, n, m)
                
                key_display = f"KEY SPLIT INTO {n} PARTS (any {m} can decrypt)\n\n"
                for idx, share in shares:
                    share_str = format_share(idx, share, n, m)
                    key_display += f"Part {idx}: {share_str}\n\n"
            except Exception as e:
                key_display = key_string  # Fallback to normal key
        
        # Handle shred original
        if options.get('shred'):
            eel.updateProgress('encrypt', 100, 'Shredding original...')()
            secure_shred_file(file_path, passes=3)
        
        return {
            'success': True,
            'key': key_display,
            'outputPath': str(output_path)
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


@eel.expose
def decrypt_file(file_path, key_or_parts, key_type='single'):
    """Decrypt a file with the given key"""
    try:
        if not file_path:
            return {'success': False, 'error': 'No file selected'}
        
        file_path = Path(file_path)
        
        # Check self-destruct
        should_destruct, reason, remaining = check_self_destruct(file_path)
        if should_destruct:
            destroy_encrypted_file(file_path)
            return {'success': False, 'error': f'File has expired: {reason}'}
        
        # Check lockout
        lockout = get_lockout_status(file_path)
        if lockout['locked']:
            return {
                'success': False,
                'error': f"File locked until {lockout['unlock_time'].strftime('%Y-%m-%d %H:%M')}"
            }
        
        # Get key bytes based on type
        key_bytes = None
        
        if key_type == 'single':
            key_bytes = key_to_bytes(key_or_parts)
            if not key_bytes:
                record_failed_attempt(file_path)
                return {'success': False, 'error': 'Invalid key format'}
        
        elif key_type == 'split':
            shares = []
            for line in key_or_parts.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                parsed = parse_share(line)
                if parsed:
                    idx, share_bytes, total, thresh = parsed
                    shares.append((idx, share_bytes))
            
            if len(shares) < 2:
                return {'success': False, 'error': 'Need at least 2 key parts'}
            
            try:
                key_bytes = combine_shares(shares)
            except Exception as e:
                return {'success': False, 'error': f'Could not combine key parts: {e}'}
        
        elif key_type == 'question':
            success, result = recover_key_from_answer(file_path, key_or_parts)
            if success:
                key_bytes = result
            else:
                record_failed_attempt(file_path)
                return {'success': False, 'error': 'Wrong answer'}
        
        # Get output path
        orig_name = file_path.stem
        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted File As",
            initialfile=orig_name
        )
        
        if not output_path:
            return {'success': False, 'error': 'No save location selected'}
        
        output_path = Path(output_path)
        
        # Progress callback
        def progress(pct, bytes_done, total_bytes, eta, message):
            eel.updateProgress('decrypt', int(pct), message)()
        
        # Decrypt
        success, result, orig = decrypt_file_with_key(
            file_path, key_bytes, output_path, progress
        )
        
        if success:
            clear_lockout(file_path)
            should_destroy, remaining = increment_destruct_counter(file_path)
            
            if should_destroy:
                destroy_encrypted_file(file_path)
                return {
                    'success': True,
                    'message': 'File decrypted. This was the FINAL use - encrypted file destroyed.',
                    'remaining': 0
                }
            
            return {
                'success': True,
                'outputPath': str(output_path),
                'remaining': remaining
            }
        else:
            if "Wrong key" in result:
                record_failed_attempt(file_path)
            return {'success': False, 'error': result}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


@eel.expose
def get_file_security_question(file_path):
    """Get the security question for a file"""
    try:
        has_q, question = get_security_question(Path(file_path))
        return {'hasQuestion': has_q, 'question': question}
    except:
        return {'hasQuestion': False, 'question': None}


def main():
    print()
    print("=" * 60)
    print("  QUANTUM FILE ENCRYPTOR - FUTURISTIC GUI")
    print("=" * 60)
    print()
    print("  Starting web interface...")
    print("  A browser window will open shortly.")
    print()
    print("  To close: Press Ctrl+C or close the browser window")
    print("=" * 60)
    print()
    
    # Start Eel with Chrome/Edge
    try:
        eel.start('index.html', size=(1200, 900), mode='chrome')
    except:
        try:
            eel.start('index.html', size=(1200, 900), mode='edge')
        except:
            # Fallback to default browser
            eel.start('index.html', size=(1200, 900))


if __name__ == '__main__':
    main()
