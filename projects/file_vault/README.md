# FileVault

A cryptographically secure file encryption tool designed for IT professionals to protect sensitive local assets.

## Features
- **AES-GCM Encryption**: Uses 256-bit AES in Galois/Counter Mode for both confidentiality and integrity verification.
- **Strong Key Derivation**: Uses PBKDF2 with SHA-256 and 100,000 iterations to derive keys from passwords.
- **Simple CLI Interface**: Easily encrypt and decrypt files with a single class.

## Grok Build Standards
- **Security**: Relies on the `cryptography` library (Standard Python security library). No "rolling your own crypto."
- **OOP Design**: Encapsulates derivation and encryption logic within the `FileVault` class.
- **Safety**: Validates data integrity during decryption; fails safely if the password is incorrect.

## Usage
```python
from vault import FileVault

vault = FileVault("your-password")
vault.encrypt_file("secrets.txt") # Produces secrets.txt.vault
vault.decrypt_file("secrets.txt.vault")
```
