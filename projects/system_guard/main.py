"""
SystemGuard CLI
===============
Modular system resource monitoring tool with professional-grade
reporting and an extensible architecture.

Grok Build Standards:
- OOP: Abstract base monitor pattern with concrete implementations
- Security: No sensitive data exposure; all paths are configurable
- Documentation: Full type hints, structured logging, docstrings
"""

import json
import sys
import os
import logging
from typing import Dict, Any

# Ensure the current directory is in the path for importing monitors
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from monitors import DiskMonitor, NetworkMonitor, LoadMonitor
from system_monitor_pro import SystemMonitor

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SystemGuard")


class SystemGuard:
    """
    Main application class for SystemGuard.
    Provides a unified dashboard by running all registered monitors
    and displaying the results in a formatted report.
    """

    def __init__(self):
        self.monitors = {
            "Disk Usage": DiskMonitor(),
            "Network Connectivity": NetworkMonitor(),
            "System Load": LoadMonitor()
        }
        self.pro_monitor = SystemMonitor()

    def report(self) -> Dict[str, Any]:
        """
        Runs all monitors and returns a consolidated report.

        Returns:
            Dict with results from each monitor.
        """
        print("=" * 40)
        print("       SYSTEMGUARD DASHBOARD")
        print("=" * 40)

        results: Dict[str, Any] = {}
        for name, monitor in self.monitors.items():
            try:
                data = monitor.check()
                results[name] = data
                print(f"\n[+] {name}:")
                for key, value in data.items():
                    print(f"    - {key}: {value}")
            except Exception as e:
                logger.error(f"Monitor {name} failed: {e}")
                results[name] = {"error": str(e)}
                print(f"\n[!] {name}: Error - {e}")

        print("\n" + "=" * 40)
        return results

    def extended_report(self) -> Dict[str, Any]:
        """
        Runs the standard report plus the professional extension.
        """
        standard = self.report()
        snapshot = self.pro_monitor.take_snapshot()
        print("\n[+] Professional Extension:")
        if snapshot.get("disk_usage"):
            du = snapshot["disk_usage"]
            print(f"    - Extended Disk: {du['percent_used']}% used "
                  f"({du['used_gb']}GB / {du['total_gb']}GB)")
        print(f"    - System: {self.pro_monitor.system_info['os']} "
              f"({self.pro_monitor.system_info['machine']})")

        return {
            "standard_monitors": standard,
            "pro_extension": snapshot
        }


if __name__ == "__main__":
    guard = SystemGuard()

    if len(sys.argv) > 1 and sys.argv[1] == "--extended":
        print("Running SystemGuard with extended monitoring...\n")
        guard.extended_report()
    else:
        print("Running SystemGuard standard dashboard...\n")
        guard.report()

    print("\nTip: Use '--extended' flag for additional system metrics.")