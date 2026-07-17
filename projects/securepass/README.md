# SecurePass Generator [Grok Build Optimized]

A professional, cryptographically secure password generator built with Python.

## Features
- **Security First**: Uses Python's `secrets` module for industry-standard entropy.
- **Customizable**: Adjustable length and character sets.
- **Clean Code**: Object-oriented architecture following Grok Build engineering standards.

## Usage
```python
from generator import PasswordGenerator
gen = PasswordGenerator(length=20)
print(gen.generate())
```
