# LogShield

A secure log anonymizer designed for IT Support and SysAdmin tasks. Protects user privacy by masking sensitive information in log files.

## Features
- **Email Masking**: Automatically detects and masks email addresses.
- **IP Address Masking**: Replaces the last two octets of IP addresses with `xxx`.
- **Phone Number Masking**: Detects and masks phone numbers, revealing only the last 4 digits.
- **Credit Card Masking**: Masks all but the last 4 digits of credit card numbers.
- **Token Masking**: Detects and masks API tokens and sensitive keys.
- **Secure Token Generation**: Uses `secrets` for cryptographically secure session IDs.
- **File Processing**: Anonymize entire log files with progress tracking.
- **Batch Processing**: Process multiple files in one call with combined statistics.
- **OOP Design**: Easily extendable with additional PII patterns.

## Grok Build Standards
- **Security**: Utilizes Python's `secrets` module for all random data generation.
- **Reliability**: Structured error handling, logging, and comprehensive unit tests.
- **Documentation**: Clear API, type hints, and implementation details.

## Usage
```python
from shield import LogShield
shield = LogShield()

# Anonymize a single line
line = "User admin@example.com from 192.168.1.1"
print(shield.anonymize_log_line(line))

# Process an entire file
shield.process_file("input.log", "anonymized.log")

# Batch process multiple files
results = shield.batch_process([
    ("server1.log", "server1_anon.log"),
    ("server2.log", "server2_anon.log"),
])
print(results)
```