# LogShield

A secure log anonymizer designed for IT Support and SysAdmin tasks. Protects user privacy by masking sensitive information in log files.

## Features
- **Email Masking**: Automatically detects and masks email addresses.
- **Secure Token Generation**: Uses `secrets` for cryptographically secure session IDs.
- **OOP Design**: Easy to extend for IP masking, credit card detection, and more.

## Grok Build Standards
- **Security**: Utilizes Python's `secrets` module for all random data generation.
- **Reliability**: Structured error handling and logging.
- **Documentation**: Clear API and implementation details.

## Usage
```python
from shield import LogShield
shield = LogShield()
shield.process_file("input.log", "anonymized.log")
```
