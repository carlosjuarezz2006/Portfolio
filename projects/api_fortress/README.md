# APIFortress

A professional API monitoring and health-check tool with concurrent endpoint checking, latency tracking, and structured reporting.

## Features
- **Concurrent Monitoring**: Thread pool-based parallel endpoint checks (configurable worker count).
- **Health Checks**: Tests endpoint availability, response status codes, and latency.
- **Expected Status Validation**: Optionally verify endpoints return a specific HTTP status code.
- **Expected Content Validation**: Verify response body contains expected text.
- **Retry Logic**: Automatic retry with exponential backoff on failure.
- **SSL Verification**: Configurable SSL certificate checking.
- **Structured Reports**: `MonitorReport` dataclass with uptime, latency statistics, and JSON export.
- **Custom Headers**: Support for authentication tokens and custom headers.

## Grok Build Standards
- **OOP Architecture**: Clean separation with `APIFortress`, `EndpointHealth`, and `MonitorReport` classes.
- **Security**: Configurable timeouts, SSL verification, and clean session management.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 20+ unit tests.

## Usage
```python
from fortress import APIFortress

fortress = APIFortress(timeout=10, verify_ssl=True)

# Check a single endpoint
health = fortress.check_endpoint("https://api.example.com/health")
print(f"Up: {health.is_up}, Latency: {health.latency:.0f}ms")

# Concurrent bulk monitoring
results = fortress.bulk_monitor([
    "https://api1.example.com",
    "https://api2.example.com",
])

# Monitor with retry
health = fortress.monitor_with_retry(
    "https://api.example.com", retries=3, backoff=1.0
)

# With expected status and content validation
health = fortress.check_endpoint(
    "https://api.example.com/status",
    expected_status=200,
    expected_text="healthy"
)

# Get report
report = fortress.get_report()
print(f"Uptime: {report.uptime_percentage:.1f}%")
print(f"Avg Latency: {report.average_latency:.0f}ms")

# Save report
fortress.save_report("health_report.json")
```

## CLI Usage
```bash
python fortress.py
```