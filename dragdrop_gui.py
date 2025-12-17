"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🖱️ DRAG AND DROP GUI - Easy File Encryption                               ║
║                                                                              ║
║   Drop files or folders onto the window to encrypt them                     ║
║                                                                              ║
║   FEATURES:                                                                  ║
║   - Drag and drop interface                                                 ║
║   - Works on Windows, macOS, Linux                                          ║
║   - Minimal dependencies (tkinter built-in)                                 ║
║   - Optional advanced GUI with tkinterdnd2                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import threading
from pathlib import Path
from typing import Callable, List, Optional

# Add local folder to path
sys.path.insert(0, str(Path(__file__).parent))


# ═══════════════════════════════════════════════════════════════════════════
# CHECK AVAILABLE GUI LIBRARIES
# ═══════════════════════════════════════════════════════════════════════════

TK_AVAILABLE = False
TKDND_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
    
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        TKDND_AVAILABLE = True
    except ImportError:
        pass
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# DROP ZONE WIDGET
# ═══════════════════════════════════════════════════════════════════════════

class DropZone:
    """
    A simple drop zone widget for encrypting files.
    """
    
    def __init__(self, on_files_dropped: Callable[[List[Path]], None] = None):
        """
        Initialize drop zone.
        
        Args:
            on_files_dropped: Callback when files are dropped
        """
        if not TK_AVAILABLE:
            raise ImportError("tkinter is required for GUI")
        
        self.on_files_dropped = on_files_dropped
        self.root = None
        self.is_running = False
    
    def _create_window(self):
        """Create the drop zone window"""
        if TKDND_AVAILABLE:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()
        
        self.root.title("🔐 Quantum Encryptor - Drop Zone")
        self.root.geometry("400x300")
        self.root.resizable(True, True)
        
        # Configure style
        self.root.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#1a1a2e')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(
            main_frame,
            text="🔐 QUANTUM ENCRYPTOR",
            font=('Segoe UI', 16, 'bold'),
            fg='#00d4ff',
            bg='#1a1a2e'
        )
        title.pack(pady=(0, 10))
        
        # Drop zone frame
        self.drop_frame = tk.Frame(
            main_frame,
            bg='#0f3460',
            highlightbackground='#00d4ff',
            highlightthickness=2,
            width=350,
            height=150
        )
        self.drop_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.drop_frame.pack_propagate(False)
        
        # Drop label
        self.drop_label = tk.Label(
            self.drop_frame,
            text="📁 Drop Files or Folders Here\n\nor click to browse",
            font=('Segoe UI', 12),
            fg='#ffffff',
            bg='#0f3460',
            cursor='hand2'
        )
        self.drop_label.pack(expand=True)
        
        # Bind click to browse
        self.drop_frame.bind('<Button-1>', self._browse_files)
        self.drop_label.bind('<Button-1>', self._browse_files)
        
        # Setup drag and drop if available
        if TKDND_AVAILABLE:
            self.drop_frame.drop_target_register(DND_FILES)
            self.drop_frame.dnd_bind('<<Drop>>', self._on_drop)
            self.drop_frame.dnd_bind('<<DragEnter>>', self._on_drag_enter)
            self.drop_frame.dnd_bind('<<DragLeave>>', self._on_drag_leave)
        else:
            # Fallback: show instruction
            self.drop_label.configure(
                text="📁 Click to Select Files\n\n(Install tkinterdnd2 for drag-drop)"
            )
        
        # Status bar
        self.status = tk.Label(
            main_frame,
            text="Ready to encrypt",
            font=('Segoe UI', 9),
            fg='#666666',
            bg='#1a1a2e'
        )
        self.status.pack(pady=(10, 0))
        
        # Buttons frame
        btn_frame = tk.Frame(main_frame, bg='#1a1a2e')
        btn_frame.pack(pady=(10, 0))
        
        # Mode selection
        self.mode_var = tk.StringVar(value="encrypt")
        
        encrypt_btn = tk.Radiobutton(
            btn_frame,
            text="Encrypt",
            variable=self.mode_var,
            value="encrypt",
            font=('Segoe UI', 10),
            fg='#00ff88',
            bg='#1a1a2e',
            selectcolor='#1a1a2e',
            activebackground='#1a1a2e'
        )
        encrypt_btn.pack(side=tk.LEFT, padx=10)
        
        decrypt_btn = tk.Radiobutton(
            btn_frame,
            text="Decrypt",
            variable=self.mode_var,
            value="decrypt",
            font=('Segoe UI', 10),
            fg='#ff6b6b',
            bg='#1a1a2e',
            selectcolor='#1a1a2e',
            activebackground='#1a1a2e'
        )
        decrypt_btn.pack(side=tk.LEFT, padx=10)
    
    def _on_drop(self, event):
        """Handle file drop"""
        # Parse dropped files (format varies by OS)
        files_str = event.data
        
        # Handle different formats
        if files_str.startswith('{'):
            # Windows format with braces
            files = []
            in_brace = False
            current = ''
            for char in files_str:
                if char == '{':
                    in_brace = True
                elif char == '}':
                    in_brace = False
                    files.append(current.strip())
                    current = ''
                elif in_brace:
                    current += char
                elif char == ' ' and not in_brace:
                    if current.strip():
                        files.append(current.strip())
                    current = ''
                else:
                    current += char
            if current.strip():
                files.append(current.strip())
        else:
            # Simple space-separated or newline-separated
            files = files_str.split()
        
        # Convert to Path objects
        paths = [Path(f) for f in files if f]
        
        self._reset_drop_style()
        self._process_files(paths)
    
    def _on_drag_enter(self, event):
        """Highlight drop zone on drag enter"""
        self.drop_frame.configure(highlightbackground='#00ff88', highlightthickness=3)
        self.drop_label.configure(fg='#00ff88', text="📂 Release to Encrypt!")
    
    def _on_drag_leave(self, event):
        """Reset drop zone on drag leave"""
        self._reset_drop_style()
    
    def _reset_drop_style(self):
        """Reset drop zone to default style"""
        self.drop_frame.configure(highlightbackground='#00d4ff', highlightthickness=2)
        if TKDND_AVAILABLE:
            self.drop_label.configure(
                fg='#ffffff',
                text="📁 Drop Files or Folders Here\n\nor click to browse"
            )
        else:
            self.drop_label.configure(
                fg='#ffffff',
                text="📁 Click to Select Files\n\n(Install tkinterdnd2 for drag-drop)"
            )
    
    def _browse_files(self, event=None):
        """Open file browser dialog"""
        mode = self.mode_var.get()
        
        if mode == "encrypt":
            files = filedialog.askopenfilenames(
                title="Select Files to Encrypt",
                filetypes=[("All Files", "*.*")]
            )
        else:
            files = filedialog.askopenfilenames(
                title="Select Files to Decrypt",
                filetypes=[("Encrypted Files", "*.qenc"), ("All Files", "*.*")]
            )
        
        if files:
            paths = [Path(f) for f in files]
            self._process_files(paths)
    
    def _process_files(self, files: List[Path]):
        """Process dropped/selected files"""
        if not files:
            return
        
        mode = self.mode_var.get()
        self.status.configure(text=f"Processing {len(files)} file(s)...")
        
        # Call the callback
        if self.on_files_dropped:
            threading.Thread(
                target=self._process_thread,
                args=(files, mode),
                daemon=True
            ).start()
    
    def _process_thread(self, files: List[Path], mode: str):
        """Process files in background thread"""
        try:
            self.on_files_dropped(files, mode)
            self.root.after(0, lambda: self.status.configure(
                text=f"✓ {len(files)} file(s) processed!"
            ))
        except Exception as e:
            self.root.after(0, lambda: self.status.configure(
                text=f"✗ Error: {str(e)}"
            ))
    
    def show(self):
        """Show the drop zone window"""
        if self.root is None:
            self._create_window()
        
        self.is_running = True
        self.root.mainloop()
        self.is_running = False
    
    def close(self):
        """Close the drop zone window"""
        if self.root:
            self.root.destroy()
            self.root = None
            self.is_running = False


# ═══════════════════════════════════════════════════════════════════════════
# PROGRESS DIALOG
# ═══════════════════════════════════════════════════════════════════════════

class ProgressDialog:
    """A progress dialog for long operations"""
    
    def __init__(self, parent=None, title: str = "Processing"):
        if not TK_AVAILABLE:
            raise ImportError("tkinter required")
        
        self.dialog = tk.Toplevel(parent) if parent else tk.Tk()
        self.dialog.title(title)
        self.dialog.geometry("400x120")
        self.dialog.resizable(False, False)
        self.dialog.configure(bg='#1a1a2e')
        
        # Make modal
        if parent:
            self.dialog.transient(parent)
            self.dialog.grab_set()
        
        # Message label
        self.message = tk.Label(
            self.dialog,
            text="Initializing...",
            font=('Segoe UI', 11),
            fg='#ffffff',
            bg='#1a1a2e'
        )
        self.message.pack(pady=(20, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(
            self.dialog,
            length=350,
            mode='determinate'
        )
        self.progress.pack(pady=10)
        
        # Percentage label
        self.percentage = tk.Label(
            self.dialog,
            text="0%",
            font=('Segoe UI', 9),
            fg='#666666',
            bg='#1a1a2e'
        )
        self.percentage.pack()
    
    def update(self, value: int, message: str = None):
        """Update progress (0-100)"""
        self.progress['value'] = value
        self.percentage.configure(text=f"{value}%")
        if message:
            self.message.configure(text=message)
        self.dialog.update()
    
    def close(self):
        """Close the dialog"""
        self.dialog.destroy()


# ═══════════════════════════════════════════════════════════════════════════
# KEY INPUT DIALOG
# ═══════════════════════════════════════════════════════════════════════════

class KeyInputDialog:
    """Dialog for entering encryption/decryption key"""
    
    def __init__(self, parent=None, mode: str = "encrypt"):
        if not TK_AVAILABLE:
            raise ImportError("tkinter required")
        
        self.dialog = tk.Toplevel(parent) if parent else tk.Tk()
        self.dialog.title("🔑 Enter Key" if mode == "decrypt" else "🔐 Encryption Key")
        self.dialog.geometry("450x200")
        self.dialog.resizable(False, False)
        self.dialog.configure(bg='#1a1a2e')
        
        # Make modal
        if parent:
            self.dialog.transient(parent)
            self.dialog.grab_set()
            self.dialog.focus_set()
        
        self.result = None
        
        # Instructions
        if mode == "encrypt":
            instruction = "Your encryption key has been generated.\nSave this key - you'll need it to decrypt!"
        else:
            instruction = "Enter your decryption key:"
        
        tk.Label(
            self.dialog,
            text=instruction,
            font=('Segoe UI', 10),
            fg='#cccccc',
            bg='#1a1a2e',
            justify=tk.CENTER
        ).pack(pady=(20, 10))
        
        # Key entry
        self.key_var = tk.StringVar()
        self.key_entry = tk.Entry(
            self.dialog,
            textvariable=self.key_var,
            font=('Consolas', 12),
            width=40,
            show='' if mode == "encrypt" else '*'
        )
        self.key_entry.pack(pady=10)
        
        # Show/hide toggle for decrypt mode
        if mode == "decrypt":
            self.show_var = tk.BooleanVar(value=False)
            show_check = tk.Checkbutton(
                self.dialog,
                text="Show key",
                variable=self.show_var,
                command=self._toggle_show,
                font=('Segoe UI', 9),
                fg='#888888',
                bg='#1a1a2e',
                selectcolor='#1a1a2e',
                activebackground='#1a1a2e'
            )
            show_check.pack()
        
        # Buttons
        btn_frame = tk.Frame(self.dialog, bg='#1a1a2e')
        btn_frame.pack(pady=15)
        
        if mode == "encrypt":
            copy_btn = tk.Button(
                btn_frame,
                text="📋 Copy Key",
                command=self._copy_key,
                font=('Segoe UI', 10),
                bg='#0f3460',
                fg='#ffffff',
                width=12
            )
            copy_btn.pack(side=tk.LEFT, padx=5)
        
        ok_btn = tk.Button(
            btn_frame,
            text="Continue",
            command=self._on_ok,
            font=('Segoe UI', 10),
            bg='#00d4ff',
            fg='#000000',
            width=12
        )
        ok_btn.pack(side=tk.LEFT, padx=5)
        
        cancel_btn = tk.Button(
            btn_frame,
            text="Cancel",
            command=self._on_cancel,
            font=('Segoe UI', 10),
            bg='#333333',
            fg='#ffffff',
            width=12
        )
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self._on_ok())
        self.dialog.bind('<Escape>', lambda e: self._on_cancel())
    
    def _toggle_show(self):
        """Toggle key visibility"""
        if self.show_var.get():
            self.key_entry.configure(show='')
        else:
            self.key_entry.configure(show='*')
    
    def _copy_key(self):
        """Copy key to clipboard"""
        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(self.key_var.get())
        messagebox.showinfo("Copied", "Key copied to clipboard!")
    
    def _on_ok(self):
        """Handle OK button"""
        self.result = self.key_var.get()
        self.dialog.destroy()
    
    def _on_cancel(self):
        """Handle Cancel button"""
        self.result = None
        self.dialog.destroy()
    
    def set_key(self, key: str):
        """Set the key value (for showing generated key)"""
        self.key_var.set(key)
    
    def show(self) -> Optional[str]:
        """Show dialog and return result"""
        self.dialog.wait_window()
        return self.result


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def launch_drop_zone(on_files_dropped: Callable = None):
    """
    Launch the drop zone GUI.
    
    Args:
        on_files_dropped: Callback function(files: List[Path], mode: str)
    """
    if not TK_AVAILABLE:
        print("ERROR: tkinter is required for GUI mode")
        print("Install with your system package manager")
        return
    
    zone = DropZone(on_files_dropped)
    zone.show()


def is_gui_available() -> bool:
    """Check if GUI is available"""
    return TK_AVAILABLE


def is_dragdrop_available() -> bool:
    """Check if drag-and-drop is available"""
    return TKDND_AVAILABLE


# Test if run directly
if __name__ == "__main__":
    def test_callback(files, mode):
        print(f"Mode: {mode}")
        for f in files:
            print(f"  - {f}")
    
    launch_drop_zone(test_callback)
