# SystemGuard CLI

A lightweight, OOP-based system monitoring tool written in Python.

## Features
- **Disk Monitoring**: Tracks total, used, and free space.
- **Network Connectivity**: Checks if the system can reach external DNS servers.
- **System Load**: Reports 1, 5, and 15-minute load averages.

## Grok Build Methodology
This project follows professional standards:
- **Object-Oriented Programming (OOP)**: Modular design with a base monitor class.
- **Error Handling**: Graceful handling of socket timeouts and OS-specific limitations.
- **No External Dependencies**: Built using standard Python libraries.

## Usage
```bash
python3 main.py
```
