import json
import sys
import os

# Add current directory to path to import monitors
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from monitors import DiskMonitor, NetworkMonitor, LoadMonitor

class SystemGuard:
    """Main application class for SystemGuard."""
    def __init__(self):
        self.monitors = {
            "Disk Usage": DiskMonitor(),
            "Network Connectivity": NetworkMonitor(),
            "System Load": LoadMonitor()
        }

    def report(self):
        """Runs all monitors and returns a consolidated report."""
        print("="*30)
        print("   SYSTEMGUARD DASHBOARD   ")
        print("="*30)
        
        results = {}
        for name, monitor in self.monitors.items():
            data = monitor.check()
            results[name] = data
            print(f"\n[+] {name}:")
            for key, value in data.items():
                print(f"    - {key}: {value}")
        
        print("\n" + "="*30)
        return results

if __name__ == "__main__":
    guard = SystemGuard()
    guard.report()
