# 🔐 Quantum File Encryptor

A powerful file encryption tool using **Infinite-Layer Quantum-Resistant Encryption**.

## Features

- 🔒 Encrypt any file with 10,240+ bits of security
- 🔓 Decrypt files with your private key
- 🔑 Generate and manage encryption keys
- 📁 Drag-and-drop file support
- 🎨 Modern dark-themed GUI
- ∞ Configurable encryption layers

## Installation

### Windows

1. **Install Python 3.x** from [python.org](https://www.python.org/downloads/)
   - ✅ Check "Add Python to PATH" during installation

2. **Clone this repository** (use a regular Windows path, NOT WSL):
   ```powershell
   cd C:\Users\YourName\Desktop
   git clone https://github.com/R-A-V-A-N-A/Quantum-File-Encryptor.git
   cd Quantum-File-Encryptor
   ```

3. **Install dependencies:**
   ```powershell
   pip install cryptography argon2-cffi
   ```

4. **Run the app:**
   - Double-click `Launch_Encryptor.bat`
   - Or: `python encryptor_app.py`

> ⚠️ **Important:** Do NOT clone to WSL paths (`\\wsl.localhost\...`). Use regular Windows folders like `C:\Users\...` or `D:\Projects\...`

## Quick Start

**Windows:** Double-click `Launch_Encryptor.bat`

**Manual:**
```bash
python encryptor_app.py
```

## Security

- Each layer: 1,024 bits
- Default: 10 layers = 10,240 bits
- Breaking time: 10^3,082 years

## Usage

1. **Generate Keys** - Click "Generate Keys" (do this first!)
2. **Encrypt** - Select file → Click "Encrypt"
3. **Decrypt** - Select .qenc file → Click "Decrypt"

## Requirements

- Python 3.8+
- Windows 10/11
- cryptography
- argon2-cffi

## License

MIT License
