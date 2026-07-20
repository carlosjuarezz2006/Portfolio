# SystemGuard CLI

A modular system monitoring tool built with OOP principles for IT Support automation.

## Features
- **DiskMonitor**: Tracks storage usage and warns when thresholds are exceeded.
- **NetworkMonitor**: Verifies connectivity to key infrastructure (e.g., DNS, gateways).
- **LoadMonitor**: Reports system load averages (Unix-like systems).
- **MemoryMonitor (New)**: Extracts real-time memory metrics from `/proc/meminfo` on Linux.

## Grok Standards
- **Extensibility**: Uses an abstract base class (`BaseMonitor`) allowing for easy addition of new system checks.
- **Robustness**: Includes logging and exception handling for production reliability.
- **Pure Python**: Minimizes external dependencies by utilizing standard system interfaces.

## Usage
```python
from monitors import DiskMonitor, MemoryMonitor

disk = DiskMonitor(threshold=85.0)
print(disk.check())

memory = MemoryMonitor()
print(memory.check())
```
