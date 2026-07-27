# LogShield

A secure log anonymizer for IT Support professionals. Replaces sensitive data (IPs, emails, tokens, phone numbers, credit cards, URLs, MAC addresses, and file paths) with secure hashes or masked values.

## Features
- **9 Detection Patterns**: Emails, IPv4, IPv6, phone numbers, credit cards, tokens, URLs, MAC addresses, and file paths.
- **File Processing**: Anonymize entire log files with structured statistics.
- **Streaming Mode**: Memory-efficient `anonymize_stream()` for large files.
- **Batch Processing**: Process multiple files in a single call.
- **Structured Reports**: `AnonymizedResult` dataclass with pattern counts, line counts, and processing time.
- **Extensible**: Easy to add new patterns or custom masking functions.

## Grok Build Standards
- **Cryptographic Security**: Uses `secrets` module for secure operations; avoids rolling custom crypto.
- **OOP Architecture**: Clean separation with `LogShield`, `AnonymizedResult` classes and pattern registry.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 25+ unit tests.

## Usage
```python
from shield import LogShield

shield = LogShield()

# Anonymize a single line
line = "User admin@example.com logged in from 192.168.1.1"
safe = shield.anonymize_log_line(line)
print(safe)  # User a***s@example.com logged in from 192.168.xxx.xxx

# Anonymize a file
result = shield.process_file("server.log", "server_anonymized.log")
print(f"Processed {result.lines_processed} lines")
print(f"Patterns masked: {result.patterns_masked}")

# Stream large files (memory efficient)
with open("large.log") as f:
    for anonymized_line in shield.anonymize_stream(f):
        print(anonymized_line)

# Batch process
results = shield.batch_process([
    ("auth.log", "auth_safe.log"),
    ("access.log", "access_safe.log"),
])
```

## Supported Patterns
| Pattern | Example Input | Masked Output |
|---------|--------------|---------------|
| Email | `admin@example.com` | `a***n@example.com` |
| IPv4 | `192.168.1.1` | `192.168.xxx.xxx` |
| IPv6 | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` | `2001:0db8:****:****:****` |
| Phone | `+1-555-123-4567` | `***4567` |
| Credit Card | `4111-1111-1111-1111` | `****-****-****-1111` |
| Token | `ghp_abcdef...7890` | `ghp_...7890` |
| URL | `https://example.com/login?token=secret` | `https://example.com/login?***masked***` |
| MAC | `00:1a:2b:3c:4d:5e` | `00:1a:2b:xx:xx:xx` |
| File Path | `/home/user/.ssh/id_rsa` | `***/id_rsa` |