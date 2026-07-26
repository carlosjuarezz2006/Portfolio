# FileVault

A professional-grade, cryptographically secure file encryption/decryption tool using **AES-256-GCM** authenticated encryption with **PBKDF2-HMAC-SHA256** key derivation.

## Features
- **AES-256-GCM Encryption**: 256-bit AES in Galois/Counter Mode for both confidentiality and integrity verification.
- **Strong Key Derivation**: PBKDF2 with HMAC-SHA256 and 600,000 iterations (OWASP 2023 recommended minimum).
- **Streaming Support**: Intelligent chunked processing for large files.
- **Batch Operations**: Encrypt or decrypt entire directories of files.
- **Base64 Mode**: Encrypt raw bytes (API keys, config values) to base64 strings.
- **Structured Reports**: Every operation returns a `VaultOperation` dataclass with timing and error details.
- **CLI Interface**: Simple command-line usage for encrypt/decrypt operations.

## Grok Build Standards
- **Cryptographic Security**: Uses `cryptography.hazmat` — never rolls custom crypto. Password validation, salt generation, and authenticated encryption are all industry-standard.
- **OOP Architecture**: Clean separation with `FileVault` class, `VaultOperation` dataclass, and single-responsibility private methods.
- **Professional Documentation**: Full type hints, comprehensive docstrings, structured logging, and 20+ unit tests.

## Usage
```python
from vault import FileVault

vault = FileVault("your-strong-password")

# Encrypt a file
result = vault.encrypt_file("secrets.txt")
# Produces: secrets.txt.vault

# Decrypt a file
result = vault.decrypt_file("secrets.txt.vault")
# Restores: secrets.txt

# Batch operations
results = vault.encrypt_batch(["file1.txt", "file2.txt"])

# Base64 mode for small data
encrypted = vault.encrypt_to_base64(b"API_KEY=sk-abc123")
decrypted = vault.decrypt_from_base64(encrypted)

# Session summary
print(vault.get_summary())
```

## CLI Usage
```bash
python vault.py encrypt myfile.txt "my-secret-password"
python vault.py decrypt myfile.txt.vault "my-secret-password"
```