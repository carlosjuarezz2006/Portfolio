# CertSentinel

A professional SSL/TLS certificate monitoring tool with expiration tracking, concurrent bulk checking, configurable alert thresholds, and structured JSON reporting.

## Features
- **Expiration Tracking**: Calculates remaining days with configurable warning/critical thresholds.
- **Concurrent Bulk Checking**: Thread pool-based parallel certificate checks for multiple domains.
- **Structured Reporting**: `CertInfo` and `CertReport` dataclasses with JSON export.
- **Multiple Status Levels**: Healthy 🟢, Warning 🟡, Critical 🟠, Expired 🔴, Error 🔴.
- **Error Handling**: Graceful handling of timeouts, DNS failures, SSL errors, and connection errors.
- **History Tracking**: All checks are logged in session history for summary and reporting.
- **Serial Number Extraction**: Captures certificate serial numbers for audit trails.
- **Configurable Thresholds**: Customizable warning and critical day thresholds.

## Grok Build Standards
- **Cryptographic Security**: Uses Python's `ssl` module with `create_default_context()` for secure defaults.
- **OOP Architecture**: Clean separation with `CertSentinel`, `CertInfo`, and `CertReport` classes.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 20+ unit tests.

## Usage
```python
from sentinel import CertSentinel

sentinel = CertSentinel(timeout=10, warn_days=30, critical_days=14)

# Single domain check
info = sentinel.get_cert_info("example.com")
print(f"Expires: {info.expires} ({info.days_left} days left)")
print(f"Issuer: {info.issuer}")

# Human-readable health status
status = sentinel.check_health("example.com")
print(status)

# Concurrent bulk check
report = sentinel.bulk_check([
    "google.com", "github.com", "stackoverflow.com"
])
print(f"Healthy: {report.healthy}, Warning: {report.warning}")
print(f"Critical: {report.critical}, Expired: {report.expired}")

# Get summary
summary = sentinel.get_summary()

# Save report
sentinel.save_report("cert_report.json")
```

## CLI Usage
```bash
python sentinel.py
```

## Alert Thresholds
| Threshold | Days Left | Status |
|-----------|-----------|--------|
| Healthy | > 30 | 🟢 |
| Warning | 15-30 | 🟡 |
| Critical | 1-14 | 🟠 |
| Expired | ≤ 0 | 🔴 |

These thresholds are configurable via the `warn_days` and `critical_days` parameters.