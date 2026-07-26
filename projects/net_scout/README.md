# NetScout

A fast, multithreaded port scanner for network diagnostics with service identification, banner grabbing, and structured JSON reporting.

## Features
- **Parallel Scanning**: Thread pool-based concurrent scanning (configurable worker count).
- **Service Identification**: Maps 30+ common ports to service names (SSH, HTTP, MySQL, etc.).
- **Banner Grabbing**: Optional service banner capture on open ports.
- **Multiple Scan Modes**: Quick (1-1024), Well-Known (1-1023), Extended (1-10000), or custom range.
- **Structured Reports**: `ScanReport` dataclass with JSON export for analysis.
- **Comparison Tool**: `compare_reports()` to diff port changes between scans.
- **CLI Interface**: Command-line with multiple scan modes.

## Grok Build Standards
- **OOP Architecture**: Clean separation with `NetScout` class, `ScanResult` and `ScanReport` dataclasses, and static utility methods.
- **Security**: No raw socket operations — uses standard Python `socket` library with proper timeouts.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 15+ unit tests.

## Usage
```python
from scout import NetScout

# Quick scan (ports 1-1024)
scout = NetScout("example.com", timeout=1.0)
report = scout.scan_quick()
NetScout.print_summary(report)

# Extended scan with banner grabbing
scout = NetScout("example.com", grab_banner=True)
report = scout.scan_extended(workers=200)

# Save report to JSON
NetScout.save_report(report, "scan_report.json")

# Compare two scans
diff = NetScout.compare_reports(report1, report2)
```

## CLI Usage
```bash
python scout.py example.com quick
python scout.py example.com extended --banner
python scout.py example.com well-known
python scout.py example.com 1-1000
```

## Scan Modes
| Mode | Port Range | Description |
|------|-----------|-------------|
| `quick` | 1-1024 | Top 1000 most common ports |
| `well-known` | 1-1023 | System/well-known ports only |
| `extended` | 1-10000 | Extended range for service discovery |
| `start-end` | Custom | Any custom port range |