# SecurePass Generator

A cryptographically secure password and passphrase generator built with Python's `secrets` module.

## Features
- **Cryptographically Secure**: Uses `secrets.choice()` for all random selection — no `random` module anywhere.
- **Entropy Calculation**: Computes and reports the exact entropy (in bits) for each generated password.
- **Strength Evaluation**: Classifies passwords as Weak, Moderate, Strong, or Very Strong based on entropy.
- **Passphrase Generation**: Generates memorable, secure passphrases from a curated word list (e.g., `swift-piano-jungle-rocket-empire-dolphin`).
- **Bulk Mode**: Generate multiple passwords at once with a single call.
- **Customizable**: Configurable length, character sets (digits, special, uppercase).

## Grok Build Standards
- **Cryptographic Security**: Pure `secrets` module usage — no predictable randomness.
- **OOP Architecture**: Clean separation with `PasswordGenerator` and `PassphraseGenerator` classes, each with single-responsibility methods.
- **Professional Documentation**: Full type hints, detailed docstrings, structured logging, and 16+ comprehensive unit tests.

## Usage
```python
from generator import PasswordGenerator, PassphraseGenerator

# Generate a strong password
gen = PasswordGenerator(length=20)
password, strength, entropy = gen.generate_with_strength()
print(f"Password: {password} [{strength} - {entropy:.1f} bits]")

# Generate a passphrase
phrase_gen = PassphraseGenerator(word_count=5)
print(phrase_gen.generate())  # e.g., "ocean-thunder-bridge-silver-forest"

# Bulk generation
for pwd, label, ent in gen.generate_bulk(3):
    print(f"  {pwd}  [{label}]")
```