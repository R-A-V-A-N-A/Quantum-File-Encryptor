"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🚨 EMERGENCY WIPE - Secure Data Destruction                               ║
║                                                                              ║
║   FEATURES:                                                                  ║
║   - Hotkey-triggered emergency wipe (Ctrl+Shift+Delete)                     ║
║   - Secure memory zeroing                                                   ║
║   - Temp file destruction                                                   ║
║   - Dead Man's Switch (auto-destroy if not checked in)                      ║
║                                                                              ║
║   INSTALL: pip install pynput (for hotkey support)                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import shutil
import secrets
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Callable, Optional, List
from dataclasses import dataclass

# Add local folder to path
sys.path.insert(0, str(Path(__file__).parent))


# ═══════════════════════════════════════════════════════════════════════════
# SECURE FILE DESTRUCTION
# ═══════════════════════════════════════════════════════════════════════════

class SecureShredder:
    """
    Securely destroy files and directories.
    
    Uses multiple overwrite passes to prevent data recovery.
    """
    
    # Overwrite patterns (DoD 5220.22-M inspired)
    PATTERNS = [
        b'\x00',  # All zeros
        b'\xFF',  # All ones
        b'\x55',  # 01010101
        b'\xAA',  # 10101010
        None,     # Random data
    ]
    
    @staticmethod
    def shred_file(file_path: Path, passes: int = 3) -> bool:
        """
        Securely destroy a file.
        
        Args:
            file_path: Path to file to destroy
            passes: Number of overwrite passes (default 3)
        
        Returns:
            True if successful
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return False
        
        if not file_path.is_file():
            return False
        
        try:
            file_size = file_path.stat().st_size
            
            # Multiple overwrite passes
            for pass_num in range(passes):
                pattern = SecureShredder.PATTERNS[pass_num % len(SecureShredder.PATTERNS)]
                
                with open(file_path, 'r+b') as f:
                    if pattern is None:
                        # Random data
                        bytes_written = 0
                        while bytes_written < file_size:
                            chunk_size = min(65536, file_size - bytes_written)
                            f.write(secrets.token_bytes(chunk_size))
                            bytes_written += chunk_size
                    else:
                        # Pattern data
                        pattern_data = pattern * 65536
                        bytes_written = 0
                        while bytes_written < file_size:
                            chunk_size = min(65536, file_size - bytes_written)
                            f.write(pattern_data[:chunk_size])
                            bytes_written += chunk_size
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            # Rename file to random name before deletion
            random_name = secrets.token_hex(16)
            new_path = file_path.parent / random_name
            file_path.rename(new_path)
            
            # Finally delete
            new_path.unlink()
            
            return True
            
        except Exception as e:
            # Best effort: try normal delete
            try:
                file_path.unlink()
            except:
                pass
            return False
    
    @staticmethod
    def shred_directory(dir_path: Path, passes: int = 3) -> int:
        """
        Securely destroy all files in a directory.
        
        Returns number of files destroyed.
        """
        dir_path = Path(dir_path)
        count = 0
        
        if not dir_path.exists() or not dir_path.is_dir():
            return 0
        
        # Shred all files
        for file_path in dir_path.rglob('*'):
            if file_path.is_file():
                if SecureShredder.shred_file(file_path, passes):
                    count += 1
        
        # Remove empty directories
        for dir_entry in sorted(dir_path.rglob('*'), reverse=True):
            if dir_entry.is_dir():
                try:
                    dir_entry.rmdir()
                except:
                    pass
        
        # Remove root directory
        try:
            dir_path.rmdir()
        except:
            pass
        
        return count


# ═══════════════════════════════════════════════════════════════════════════
# MEMORY WIPE
# ═══════════════════════════════════════════════════════════════════════════

class MemoryWiper:
    """
    Wipe sensitive data from memory.
    """
    
    # Registry of sensitive data to wipe
    _sensitive_data: List = []
    _lock = threading.Lock()
    
    @classmethod
    def register(cls, data: bytearray) -> None:
        """Register sensitive data for potential emergency wipe"""
        with cls._lock:
            cls._sensitive_data.append(data)
    
    @classmethod
    def unregister(cls, data: bytearray) -> None:
        """Unregister data (e.g., after it's been securely zeroed)"""
        with cls._lock:
            try:
                cls._sensitive_data.remove(data)
            except ValueError:
                pass
    
    @classmethod
    def wipe_all(cls) -> int:
        """Wipe all registered sensitive data"""
        count = 0
        with cls._lock:
            for data in cls._sensitive_data:
                if isinstance(data, bytearray):
                    for i in range(len(data)):
                        data[i] = 0
                    count += 1
            cls._sensitive_data.clear()
        return count
    
    @staticmethod
    def wipe(data: bytearray) -> None:
        """Wipe a specific bytearray"""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0


# ═══════════════════════════════════════════════════════════════════════════
# EMERGENCY WIPE SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

class EmergencyWipe:
    """
    Emergency data destruction system.
    
    Triggered by hotkey or programmatically.
    """
    
    def __init__(self, temp_dirs: List[Path] = None):
        """
        Initialize emergency wipe system.
        
        Args:
            temp_dirs: Directories to wipe on emergency (default: system temp)
        """
        self.temp_dirs = temp_dirs or []
        self._hotkey_listener = None
        self._callbacks: List[Callable] = []
        self._enabled = False
    
    def add_temp_dir(self, path: Path) -> None:
        """Add directory to emergency wipe list"""
        self.temp_dirs.append(Path(path))
    
    def add_callback(self, callback: Callable) -> None:
        """Add callback to run on emergency wipe"""
        self._callbacks.append(callback)
    
    def trigger(self) -> dict:
        """
        Trigger emergency wipe.
        
        Returns stats about what was wiped.
        """
        stats = {
            'memory_wiped': 0,
            'files_wiped': 0,
            'callbacks_run': 0,
            'errors': []
        }
        
        # Run callbacks first
        for callback in self._callbacks:
            try:
                callback()
                stats['callbacks_run'] += 1
            except Exception as e:
                stats['errors'].append(str(e))
        
        # Wipe memory
        stats['memory_wiped'] = MemoryWiper.wipe_all()
        
        # Wipe temp directories
        for temp_dir in self.temp_dirs:
            try:
                count = SecureShredder.shred_directory(temp_dir)
                stats['files_wiped'] += count
            except Exception as e:
                stats['errors'].append(str(e))
        
        return stats
    
    def start_hotkey_listener(self, hotkey: str = '<ctrl>+<shift>+<delete>') -> bool:
        """
        Start listening for emergency hotkey.
        
        Default: Ctrl+Shift+Delete
        
        Returns True if listener started successfully.
        """
        try:
            from pynput import keyboard
        except ImportError:
            return False
        
        # Parse hotkey
        keys = set()
        if '<ctrl>' in hotkey.lower():
            keys.add(keyboard.Key.ctrl)
        if '<shift>' in hotkey.lower():
            keys.add(keyboard.Key.shift)
        if '<delete>' in hotkey.lower():
            keys.add(keyboard.Key.delete)
        
        current_keys = set()
        
        def on_press(key):
            if key in keys:
                current_keys.add(key)
            if current_keys == keys:
                self.trigger()
        
        def on_release(key):
            if key in current_keys:
                current_keys.remove(key)
        
        self._hotkey_listener = keyboard.Listener(
            on_press=on_press,
            on_release=on_release
        )
        self._hotkey_listener.start()
        self._enabled = True
        
        return True
    
    def stop_hotkey_listener(self) -> None:
        """Stop the hotkey listener"""
        if self._hotkey_listener:
            self._hotkey_listener.stop()
            self._hotkey_listener = None
        self._enabled = False


# ═══════════════════════════════════════════════════════════════════════════
# DEAD MAN'S SWITCH
# ═══════════════════════════════════════════════════════════════════════════

class DeadMansSwitch:
    """
    Auto-destroy files if user doesn't check in within deadline.
    
    Use case: Protect sensitive files if user is unable to access them.
    """
    
    CONFIG_FILE = '.deadman_config.json'
    
    def __init__(self, config_dir: Path = None):
        """
        Initialize Dead Man's Switch.
        
        Args:
            config_dir: Directory for config file (default: user home)
        """
        self.config_dir = Path(config_dir) if config_dir else Path.home() / '.quantum_encryptor'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / self.CONFIG_FILE
        
        # Make config hidden on Windows
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(self.config_dir), 0x02)
        except:
            pass
    
    def _load_config(self) -> dict:
        """Load configuration"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {'active': False, 'files': [], 'deadline': None, 'last_checkin': None}
    
    def _save_config(self, config: dict) -> None:
        """Save configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def arm(self, deadline_hours: int, files: List[Path] = None) -> datetime:
        """
        Arm the dead man's switch.
        
        Args:
            deadline_hours: Hours until destruction if no check-in
            files: Files to destroy (if None, uses previously registered files)
        
        Returns:
            Deadline datetime
        """
        config = self._load_config()
        
        deadline = datetime.now() + timedelta(hours=deadline_hours)
        
        config['active'] = True
        config['deadline'] = deadline.isoformat()
        config['last_checkin'] = datetime.now().isoformat()
        
        if files:
            config['files'] = [str(f) for f in files]
        
        self._save_config(config)
        
        return deadline
    
    def checkin(self) -> Tuple[bool, datetime]:
        """
        Check in to reset the deadline.
        
        Returns:
            (success, new_deadline)
        """
        config = self._load_config()
        
        if not config['active']:
            return False, None
        
        # Calculate new deadline based on original interval
        old_deadline = datetime.fromisoformat(config['deadline'])
        old_checkin = datetime.fromisoformat(config['last_checkin'])
        interval = old_deadline - old_checkin
        
        new_deadline = datetime.now() + interval
        
        config['last_checkin'] = datetime.now().isoformat()
        config['deadline'] = new_deadline.isoformat()
        
        self._save_config(config)
        
        return True, new_deadline
    
    def disarm(self) -> bool:
        """Disarm the switch"""
        config = self._load_config()
        config['active'] = False
        self._save_config(config)
        return True
    
    def check_trigger(self) -> Tuple[bool, Optional[dict]]:
        """
        Check if switch should trigger.
        
        Returns:
            (should_trigger, config_if_triggered)
        """
        config = self._load_config()
        
        if not config['active']:
            return False, None
        
        deadline = datetime.fromisoformat(config['deadline'])
        
        if datetime.now() > deadline:
            return True, config
        
        return False, None
    
    def trigger(self) -> dict:
        """
        Trigger the switch (destroy files).
        
        Returns stats about destruction.
        """
        config = self._load_config()
        
        stats = {
            'files_destroyed': 0,
            'files_failed': 0,
            'errors': []
        }
        
        for file_path in config.get('files', []):
            try:
                path = Path(file_path)
                if path.is_file():
                    if SecureShredder.shred_file(path):
                        stats['files_destroyed'] += 1
                    else:
                        stats['files_failed'] += 1
                elif path.is_dir():
                    count = SecureShredder.shred_directory(path)
                    stats['files_destroyed'] += count
            except Exception as e:
                stats['files_failed'] += 1
                stats['errors'].append(str(e))
        
        # Disarm after triggering
        self.disarm()
        
        return stats
    
    def get_status(self) -> dict:
        """Get current status of the switch"""
        config = self._load_config()
        
        if not config['active']:
            return {'active': False}
        
        deadline = datetime.fromisoformat(config['deadline'])
        remaining = deadline - datetime.now()
        
        return {
            'active': True,
            'deadline': config['deadline'],
            'last_checkin': config['last_checkin'],
            'remaining_seconds': remaining.total_seconds(),
            'remaining_hours': remaining.total_seconds() / 3600,
            'files_count': len(config.get('files', []))
        }
    
    def add_file(self, file_path: Path) -> None:
        """Add file to destruction list"""
        config = self._load_config()
        file_str = str(file_path)
        if file_str not in config.get('files', []):
            config.setdefault('files', []).append(file_str)
            self._save_config(config)
    
    def remove_file(self, file_path: Path) -> None:
        """Remove file from destruction list"""
        config = self._load_config()
        file_str = str(file_path)
        if file_str in config.get('files', []):
            config['files'].remove(file_str)
            self._save_config(config)


# ═══════════════════════════════════════════════════════════════════════════
# STARTUP CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_deadman_on_startup() -> Optional[dict]:
    """
    Check dead man's switch on application startup.
    
    Should be called when the application starts.
    
    Returns:
        Destruction stats if triggered, None otherwise.
    """
    switch = DeadMansSwitch()
    should_trigger, config = switch.check_trigger()
    
    if should_trigger:
        return switch.trigger()
    
    return None


# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCES
# ═══════════════════════════════════════════════════════════════════════════

_emergency_wipe = None

def get_emergency_wipe() -> EmergencyWipe:
    """Get global emergency wipe instance"""
    global _emergency_wipe
    if _emergency_wipe is None:
        _emergency_wipe = EmergencyWipe()
    return _emergency_wipe
