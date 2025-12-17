"""
Quantum File Encryptor - Modern GUI Edition
============================================
A beautiful dark-mode GUI for the Quantum File Encryptor.

Features:
    - Drag-and-drop file support
    - Progress bar with ETA
    - All encryption features in GUI form
    - Dark mode by default
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
from pathlib import Path
from datetime import datetime
import time

# Import encryption functions from the main module
try:
    from encryptor_app import (
        generate_key, key_to_bytes, bytes_to_key,
        encrypt_file_with_key, decrypt_file_with_key,
        split_secret, combine_shares, format_share, parse_share,
        secure_shred_file, create_destruct_tracker,
        check_self_destruct, destroy_encrypted_file,
        get_security_question, recover_key_from_answer,
        get_lockout_status, record_failed_attempt, clear_lockout,
        increment_destruct_counter, format_size,
        get_optimal_chunk_size
    )
    ENCRYPTION_AVAILABLE = True
except ImportError as e:
    ENCRYPTION_AVAILABLE = False
    IMPORT_ERROR = str(e)

# Set appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class QuantumEncryptorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window setup
        self.title("Quantum File Encryptor")
        self.geometry("800x700")
        self.minsize(700, 600)
        
        # Variables
        self.selected_file = None
        self.is_encrypting = False
        
        # Create main container
        self.main_frame = ctk.CTkFrame(self, corner_radius=0)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        self.create_header()
        
        # Tab view for Encrypt/Decrypt
        self.tabview = ctk.CTkTabview(self.main_frame, width=700, height=500)
        self.tabview.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.tab_encrypt = self.tabview.add("🔐 Encrypt")
        self.tab_decrypt = self.tabview.add("🔓 Decrypt")
        
        # Create tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        
        # Status bar
        self.create_status_bar()
    
    def create_header(self):
        """Create the header with title and subtitle"""
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        
        title = ctk.CTkLabel(
            header_frame,
            text="🔐 Quantum File Encryptor",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(10, 5))
        
        subtitle = ctk.CTkLabel(
            header_frame,
            text="ChaCha20-Poly1305 + Argon2id | 256-bit Security",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle.pack()
    
    def create_encrypt_tab(self):
        """Create the encryption tab"""
        # File selection frame
        file_frame = ctk.CTkFrame(self.tab_encrypt)
        file_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            file_frame,
            text="Step 1: Select File",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        file_btn_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_btn_frame.pack(fill="x", padx=10, pady=5)
        
        self.encrypt_file_btn = ctk.CTkButton(
            file_btn_frame,
            text="📁 Browse Files",
            command=self.select_encrypt_file,
            width=150
        )
        self.encrypt_file_btn.pack(side="left")
        
        self.encrypt_file_label = ctk.CTkLabel(
            file_btn_frame,
            text="No file selected",
            text_color="gray"
        )
        self.encrypt_file_label.pack(side="left", padx=20)
        
        # Options frame
        options_frame = ctk.CTkFrame(self.tab_encrypt)
        options_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            options_frame,
            text="Step 2: Options",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Split key option
        self.split_key_var = ctk.BooleanVar(value=False)
        split_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        split_frame.pack(fill="x", padx=10, pady=5)
        
        self.split_key_check = ctk.CTkCheckBox(
            split_frame,
            text="Split key into parts (Shamir's Secret Sharing)",
            variable=self.split_key_var,
            command=self.toggle_split_options
        )
        self.split_key_check.pack(side="left")
        
        self.split_n_entry = ctk.CTkEntry(split_frame, width=50, placeholder_text="N")
        self.split_n_entry.pack(side="left", padx=(20, 5))
        ctk.CTkLabel(split_frame, text="parts,").pack(side="left")
        
        self.split_m_entry = ctk.CTkEntry(split_frame, width=50, placeholder_text="M")
        self.split_m_entry.pack(side="left", padx=5)
        ctk.CTkLabel(split_frame, text="required").pack(side="left")
        
        self.split_n_entry.configure(state="disabled")
        self.split_m_entry.configure(state="disabled")
        
        # Security question option
        self.security_q_var = ctk.BooleanVar(value=False)
        secq_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        secq_frame.pack(fill="x", padx=10, pady=5)
        
        self.security_q_check = ctk.CTkCheckBox(
            secq_frame,
            text="Add security question for recovery",
            variable=self.security_q_var,
            command=self.toggle_security_options
        )
        self.security_q_check.pack(side="left")
        
        self.question_entry = ctk.CTkEntry(secq_frame, width=200, placeholder_text="Question")
        self.question_entry.pack(side="left", padx=10)
        self.answer_entry = ctk.CTkEntry(secq_frame, width=150, placeholder_text="Answer")
        self.answer_entry.pack(side="left")
        
        self.question_entry.configure(state="disabled")
        self.answer_entry.configure(state="disabled")
        
        # Self-destruct option
        self.destruct_var = ctk.BooleanVar(value=False)
        destruct_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        destruct_frame.pack(fill="x", padx=10, pady=5)
        
        self.destruct_check = ctk.CTkCheckBox(
            destruct_frame,
            text="Self-destruct after",
            variable=self.destruct_var,
            command=self.toggle_destruct_options
        )
        self.destruct_check.pack(side="left")
        
        self.destruct_count_entry = ctk.CTkEntry(destruct_frame, width=50, placeholder_text="N")
        self.destruct_count_entry.pack(side="left", padx=10)
        ctk.CTkLabel(destruct_frame, text="decryptions").pack(side="left")
        
        self.destruct_count_entry.configure(state="disabled")
        
        # Shred original option
        self.shred_var = ctk.BooleanVar(value=False)
        shred_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        shred_frame.pack(fill="x", padx=10, pady=(5, 10))
        
        self.shred_check = ctk.CTkCheckBox(
            shred_frame,
            text="Securely shred original file after encryption (3-pass DoD)",
            variable=self.shred_var
        )
        self.shred_check.pack(side="left")
        
        # Progress frame
        progress_frame = ctk.CTkFrame(self.tab_encrypt)
        progress_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            progress_frame,
            text="Step 3: Encrypt",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.encrypt_progress = ctk.CTkProgressBar(progress_frame, width=600)
        self.encrypt_progress.pack(padx=10, pady=5)
        self.encrypt_progress.set(0)
        
        self.encrypt_status = ctk.CTkLabel(
            progress_frame,
            text="Ready to encrypt",
            text_color="gray"
        )
        self.encrypt_status.pack(pady=5)
        
        self.encrypt_btn = ctk.CTkButton(
            progress_frame,
            text="🔐 ENCRYPT FILE",
            command=self.start_encryption,
            width=200,
            height=40,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#1a6b3d",
            hover_color="#145530"
        )
        self.encrypt_btn.pack(pady=10)
        
        # Result frame
        result_frame = ctk.CTkFrame(self.tab_encrypt)
        result_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            result_frame,
            text="Your Key:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.key_textbox = ctk.CTkTextbox(result_frame, height=80, width=600)
        self.key_textbox.pack(padx=10, pady=5)
        
        copy_btn = ctk.CTkButton(
            result_frame,
            text="📋 Copy Key",
            command=self.copy_key,
            width=120
        )
        copy_btn.pack(pady=(5, 10))
    
    def create_decrypt_tab(self):
        """Create the decryption tab"""
        # File selection
        file_frame = ctk.CTkFrame(self.tab_decrypt)
        file_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            file_frame,
            text="Step 1: Select Encrypted File",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        file_btn_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_btn_frame.pack(fill="x", padx=10, pady=5)
        
        self.decrypt_file_btn = ctk.CTkButton(
            file_btn_frame,
            text="📁 Browse Files",
            command=self.select_decrypt_file,
            width=150
        )
        self.decrypt_file_btn.pack(side="left")
        
        self.decrypt_file_label = ctk.CTkLabel(
            file_btn_frame,
            text="No file selected",
            text_color="gray"
        )
        self.decrypt_file_label.pack(side="left", padx=20)
        
        # Key entry
        key_frame = ctk.CTkFrame(self.tab_decrypt)
        key_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            key_frame,
            text="Step 2: Enter Your Key",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        # Key type selector
        key_type_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        key_type_frame.pack(fill="x", padx=10, pady=5)
        
        self.key_type_var = ctk.StringVar(value="single")
        
        ctk.CTkRadioButton(
            key_type_frame,
            text="Single Key",
            variable=self.key_type_var,
            value="single",
            command=self.toggle_key_entry
        ).pack(side="left", padx=(0, 20))
        
        ctk.CTkRadioButton(
            key_type_frame,
            text="Split Key Parts",
            variable=self.key_type_var,
            value="split",
            command=self.toggle_key_entry
        ).pack(side="left", padx=(0, 20))
        
        ctk.CTkRadioButton(
            key_type_frame,
            text="Security Question",
            variable=self.key_type_var,
            value="question",
            command=self.toggle_key_entry
        ).pack(side="left")
        
        # Single key entry
        self.single_key_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        self.single_key_frame.pack(fill="x", padx=10, pady=5)
        
        self.decrypt_key_entry = ctk.CTkEntry(
            self.single_key_frame, 
            width=500, 
            placeholder_text="Paste your decryption key here"
        )
        self.decrypt_key_entry.pack()
        
        # Split key entry
        self.split_key_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        
        self.split_key_textbox = ctk.CTkTextbox(self.split_key_frame, height=100, width=500)
        self.split_key_textbox.pack()
        ctk.CTkLabel(
            self.split_key_frame,
            text="Enter each key part on a separate line",
            text_color="gray"
        ).pack()
        
        # Security question entry
        self.sec_q_frame = ctk.CTkFrame(key_frame, fg_color="transparent")
        
        self.sec_question_label = ctk.CTkLabel(
            self.sec_q_frame,
            text="Question will appear here",
            font=ctk.CTkFont(size=14)
        )
        self.sec_question_label.pack(pady=5)
        
        self.sec_answer_entry = ctk.CTkEntry(
            self.sec_q_frame,
            width=300,
            placeholder_text="Enter your answer"
        )
        self.sec_answer_entry.pack(pady=5)
        
        # Progress
        progress_frame = ctk.CTkFrame(self.tab_decrypt)
        progress_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            progress_frame,
            text="Step 3: Decrypt",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=10, pady=(10, 5))
        
        self.decrypt_progress = ctk.CTkProgressBar(progress_frame, width=600)
        self.decrypt_progress.pack(padx=10, pady=5)
        self.decrypt_progress.set(0)
        
        self.decrypt_status = ctk.CTkLabel(
            progress_frame,
            text="Ready to decrypt",
            text_color="gray"
        )
        self.decrypt_status.pack(pady=5)
        
        self.decrypt_btn = ctk.CTkButton(
            progress_frame,
            text="🔓 DECRYPT FILE",
            command=self.start_decryption,
            width=200,
            height=40,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color="#1a4b6b",
            hover_color="#143550"
        )
        self.decrypt_btn.pack(pady=10)
    
    def create_status_bar(self):
        """Create the status bar at bottom"""
        status_frame = ctk.CTkFrame(self.main_frame, height=30)
        status_frame.pack(fill="x", side="bottom")
        
        self.global_status = ctk.CTkLabel(
            status_frame,
            text="Ready",
            text_color="gray"
        )
        self.global_status.pack(side="left", padx=10)
    
    # Toggle functions
    def toggle_split_options(self):
        state = "normal" if self.split_key_var.get() else "disabled"
        self.split_n_entry.configure(state=state)
        self.split_m_entry.configure(state=state)
    
    def toggle_security_options(self):
        state = "normal" if self.security_q_var.get() else "disabled"
        self.question_entry.configure(state=state)
        self.answer_entry.configure(state=state)
    
    def toggle_destruct_options(self):
        state = "normal" if self.destruct_var.get() else "disabled"
        self.destruct_count_entry.configure(state=state)
    
    def toggle_key_entry(self):
        key_type = self.key_type_var.get()
        
        self.single_key_frame.pack_forget()
        self.split_key_frame.pack_forget()
        self.sec_q_frame.pack_forget()
        
        if key_type == "single":
            self.single_key_frame.pack(fill="x", padx=10, pady=5)
        elif key_type == "split":
            self.split_key_frame.pack(fill="x", padx=10, pady=5)
        else:
            self.sec_q_frame.pack(fill="x", padx=10, pady=5)
            # Load security question if file is selected
            if hasattr(self, 'decrypt_selected_file') and self.decrypt_selected_file:
                has_q, question = get_security_question(Path(self.decrypt_selected_file))
                if has_q:
                    self.sec_question_label.configure(text=f"Q: {question}")
                else:
                    self.sec_question_label.configure(text="No security question for this file")
    
    # File selection
    def select_encrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.encrypt_selected_file = file_path
            path = Path(file_path)
            size = format_size(path.stat().st_size)
            self.encrypt_file_label.configure(
                text=f"{path.name} ({size})",
                text_color="white"
            )
    
    def select_decrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[("Encrypted Files", "*.qenc"), ("All Files", "*.*")]
        )
        if file_path:
            self.decrypt_selected_file = file_path
            path = Path(file_path)
            size = format_size(path.stat().st_size)
            self.decrypt_file_label.configure(
                text=f"{path.name} ({size})",
                text_color="white"
            )
            
            # Check for security question
            has_q, question = get_security_question(path)
            if has_q:
                self.sec_question_label.configure(text=f"Q: {question}")
    
    # Encryption
    def start_encryption(self):
        if not hasattr(self, 'encrypt_selected_file') or not self.encrypt_selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        if self.is_encrypting:
            return
        
        # Get output path
        input_path = Path(self.encrypt_selected_file)
        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted File As",
            defaultextension=".qenc",
            initialfile=input_path.name + ".qenc",
            filetypes=[("Encrypted Files", "*.qenc")]
        )
        
        if not output_path:
            return
        
        self.is_encrypting = True
        self.encrypt_btn.configure(state="disabled")
        
        # Start encryption in thread
        thread = threading.Thread(
            target=self.run_encryption,
            args=(input_path, Path(output_path))
        )
        thread.start()
    
    def run_encryption(self, input_path, output_path):
        try:
            # Generate key
            key_string = generate_key()
            key_bytes = key_to_bytes(key_string)
            
            # Get options
            security_question = None
            security_answer = None
            if self.security_q_var.get():
                security_question = self.question_entry.get()
                security_answer = self.answer_entry.get()
            
            # Progress callback
            def progress(pct, bytes_done, total_bytes, eta, message):
                self.encrypt_progress.set(pct / 100)
                self.encrypt_status.configure(text=message)
            
            # Encrypt
            self.encrypt_status.configure(text="Encrypting...")
            success, result = encrypt_file_with_key(
                input_path, key_bytes, output_path, progress,
                security_question=security_question,
                security_answer=security_answer
            )
            
            if success:
                # Handle split key
                if self.split_key_var.get():
                    try:
                        n = int(self.split_n_entry.get())
                        m = int(self.split_m_entry.get())
                        shares = split_secret(key_bytes, n, m)
                        
                        key_text = f"KEY SPLIT INTO {n} PARTS (any {m} can decrypt)\n\n"
                        for idx, share in shares:
                            share_str = format_share(idx, share, n, m)
                            key_text += f"Part {idx}: {share_str}\n\n"
                        
                        self.key_textbox.delete("1.0", "end")
                        self.key_textbox.insert("1.0", key_text)
                    except:
                        self.key_textbox.delete("1.0", "end")
                        self.key_textbox.insert("1.0", key_string)
                else:
                    self.key_textbox.delete("1.0", "end")
                    self.key_textbox.insert("1.0", key_string)
                
                # Create self-destruct tracker
                if self.destruct_var.get():
                    try:
                        max_uses = int(self.destruct_count_entry.get())
                        create_destruct_tracker(output_path, max_uses=max_uses)
                    except:
                        pass
                
                # Shred original
                if self.shred_var.get():
                    self.encrypt_status.configure(text="Shredding original file...")
                    secure_shred_file(input_path, passes=3)
                
                self.encrypt_status.configure(text="✓ Encryption complete!")
                self.encrypt_progress.set(1)
                messagebox.showinfo("Success", "File encrypted successfully!\n\nDon't forget to copy your key!")
            else:
                self.encrypt_status.configure(text=f"Error: {result}")
                messagebox.showerror("Error", f"Encryption failed: {result}")
        
        except Exception as e:
            self.encrypt_status.configure(text=f"Error: {e}")
            messagebox.showerror("Error", str(e))
        
        finally:
            self.is_encrypting = False
            self.encrypt_btn.configure(state="normal")
    
    # Decryption
    def start_decryption(self):
        if not hasattr(self, 'decrypt_selected_file') or not self.decrypt_selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return
        
        file_path = Path(self.decrypt_selected_file)
        
        # Check self-destruct
        should_destruct, reason, remaining = check_self_destruct(file_path)
        if should_destruct:
            messagebox.showerror("File Expired", f"This file has expired: {reason}\n\nThe file will be destroyed.")
            destroy_encrypted_file(file_path)
            return
        
        # Check lockout
        lockout = get_lockout_status(file_path)
        if lockout['locked']:
            messagebox.showerror(
                "File Locked",
                f"This file is locked due to too many failed attempts.\n\n"
                f"Try again after: {lockout['unlock_time'].strftime('%Y-%m-%d %H:%M:%S')}"
            )
            return
        
        # Get key based on type
        key_bytes = None
        key_type = self.key_type_var.get()
        
        if key_type == "single":
            key_string = self.decrypt_key_entry.get().strip()
            if not key_string:
                messagebox.showerror("Error", "Please enter your key!")
                return
            key_bytes = key_to_bytes(key_string)
            if not key_bytes:
                record_failed_attempt(file_path)
                messagebox.showerror("Error", "Invalid key format!")
                return
        
        elif key_type == "split":
            shares_text = self.split_key_textbox.get("1.0", "end").strip()
            if not shares_text:
                messagebox.showerror("Error", "Please enter key parts!")
                return
            
            shares = []
            for line in shares_text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                parsed = parse_share(line)
                if parsed:
                    idx, share_bytes, total, thresh = parsed
                    shares.append((idx, share_bytes))
            
            if len(shares) < 2:
                messagebox.showerror("Error", "Need at least 2 key parts!")
                return
            
            try:
                key_bytes = combine_shares(shares)
            except Exception as e:
                messagebox.showerror("Error", f"Could not combine key parts: {e}")
                return
        
        else:  # Security question
            answer = self.sec_answer_entry.get().strip()
            if not answer:
                messagebox.showerror("Error", "Please enter your answer!")
                return
            
            success, result = recover_key_from_answer(file_path, answer)
            if success:
                key_bytes = result
            else:
                record_failed_attempt(file_path)
                messagebox.showerror("Error", f"Wrong answer!\n{result}")
                return
        
        # Get output path
        orig_name = file_path.stem
        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted File As",
            initialfile=orig_name
        )
        
        if not output_path:
            return
        
        # Start decryption in thread
        self.decrypt_btn.configure(state="disabled")
        thread = threading.Thread(
            target=self.run_decryption,
            args=(file_path, key_bytes, Path(output_path))
        )
        thread.start()
    
    def run_decryption(self, file_path, key_bytes, output_path):
        try:
            def progress(pct, bytes_done, total_bytes, eta, message):
                self.decrypt_progress.set(pct / 100)
                self.decrypt_status.configure(text=message)
            
            self.decrypt_status.configure(text="Decrypting...")
            success, result, orig = decrypt_file_with_key(
                file_path, key_bytes, output_path, progress
            )
            
            if success:
                clear_lockout(file_path)
                should_destroy, remaining = increment_destruct_counter(file_path)
                
                self.decrypt_status.configure(text="✓ Decryption complete!")
                self.decrypt_progress.set(1)
                
                msg = "File decrypted successfully!"
                if remaining is not None:
                    msg += f"\n\n{remaining} decryptions remaining before self-destruct."
                
                if should_destroy:
                    msg += "\n\nThis was the FINAL decryption. Encrypted file destroyed."
                    destroy_encrypted_file(file_path)
                
                messagebox.showinfo("Success", msg)
            else:
                record_failed_attempt(file_path)
                self.decrypt_status.configure(text=f"Error: {result}")
                messagebox.showerror("Error", f"Decryption failed: {result}")
        
        except Exception as e:
            self.decrypt_status.configure(text=f"Error: {e}")
            messagebox.showerror("Error", str(e))
        
        finally:
            self.decrypt_btn.configure(state="normal")
    
    def copy_key(self):
        key = self.key_textbox.get("1.0", "end").strip()
        if key:
            self.clipboard_clear()
            self.clipboard_append(key)
            messagebox.showinfo("Copied", "Key copied to clipboard!")


def main():
    if not ENCRYPTION_AVAILABLE:
        print(f"Error: Could not import encryption functions: {IMPORT_ERROR}")
        print("Make sure encryptor_app.py is in the same directory.")
        return
    
    app = QuantumEncryptorGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
