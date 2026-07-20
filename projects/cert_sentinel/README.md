# CertSentinel

A professional SSL/TLS certificate monitoring tool designed for IT professionals to track domain security health.

## Features
- **Expiration Tracking**: Calculates remaining days until certificate expiration.
- **Health Checks**: Provides color-coded status (Healthy, Warning, Critical) based on expiration proximity.
- **Issuer Identification**: Identifies the certificate authority (CA) that issued the certificate.
- **Timeout Management**: Configurable connection timeouts to prevent hanging on unresponsive servers.

## Grok Build Standards
- **OOP Principles**: Encapsulates logic within the `CertSentinel` class for reusability.
- **Security**: Uses Python's built-in `ssl` module with default secure contexts.
- **Documentation**: Clear Docstrings and type hinting for professional maintainability.

## Usage
```python
from sentinel import CertSentinel

sentinel = CertSentinel()
status = sentinel.check_health("example.com")
print(status)

info = sentinel.get_cert_info("example.com")
print(f"Expires on: {info['expires']}")
```
