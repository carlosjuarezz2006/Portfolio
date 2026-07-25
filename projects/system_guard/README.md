# SystemGuard CLI

A modular system resource monitoring tool with professional-grade reporting and an extensible architecture.

## Features
- **Disk Usage Monitor**: Tracks disk usage with custom threshold warnings.
- **Network Connectivity Monitor**: Checks reachability of external hosts via TCP sockets.
- **System Load Monitor**: Reports 1, 5, and 15-minute load averages.
- **Memory Monitor**: Cross-platform memory usage tracking (Linux with procfs, with extensible fallback).
- **Professional Extension**: Extended `SystemMonitor` class with snapshot history, persistent JSON reporting, and summary statistics.
- **CLI Interface**: Standard dashboard and `--extended` mode for additional metrics.

## Grok Build Standards
- **OOP Architecture**: Abstract base class (`BaseMonitor`) with concrete implementations, plus an extended `SystemMonitor` class.
- **Security**: No sensitive data exposure; all paths and thresholds configurable.
- **Documentation**: Full type hints, structured logging, docstrings, and 16+ comprehensive unit tests.

## Usage
```bash
# Standard dashboard
python main.py

# Extended mode with additional system metrics
python main.py --extended
```

## Modules
| Module | Class | Description |
|--------|-------|-------------|
| `monitors.py` | `DiskMonitor` | Tracks disk usage percentage and thresholds |
| `monitors.py` | `NetworkMonitor` | Checks TCP connectivity to external hosts |
| `monitors.py` | `LoadMonitor` | Reports system load averages |
| `monitors.py` | `MemoryMonitor` | Reports memory usage on Linux |
| `system_monitor_pro.py` | `SystemMonitor` | Extended monitoring with snapshot history |
| `main.py` | `SystemGuard` | Unified CLI dashboard orchestrator |