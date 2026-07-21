# NetScout

NetScout is a professional-grade, multithreaded port scanner designed for IT Support and network diagnostics.

## Features
- **High Performance**: Uses `concurrent.futures` ThreadPoolExecutor for fast scanning of large port ranges.
- **Robust Resolution**: Automatically resolves hostnames to IP addresses.
- **Clean Logging**: Uses the standard `logging` library for professional status reporting.
- **OOP Design**: Encapsulated logic for easy integration into larger automation suites.

## Grok Build Standards
- **OOP Principles**: Logical separation of concerns within the `NetScout` class.
- **Efficiency**: Multithreaded execution to minimize wait times during network timeouts.
- **Documentation**: Comprehensive docstrings and clear logging.

## Usage
```python
from scout import NetScout

scout = NetScout("example.com")
open_ports = scout.scan_range(1, 1024, workers=50)
print(f"Found open ports: {open_ports}")
```
