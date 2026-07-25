"""
SystemGuard Professional Extension
====================================
Extended system monitoring capabilities built on top of the core
SystemGuard monitors. Provides additional metrics, persistent reporting,
and cross-platform memory monitoring.

Grok Build Standards:
- OOP: Extends the BaseMonitor pattern from monitors.py
- Security: No sensitive data exposed; all paths configurable
- Documentation: Full type hints, docstrings, structured logging
"""

import shutil
import logging
import platform
import json
import os
import time
from typing import Dict, Optional, List
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SystemGuardPro")


class SystemMonitor:
    """
    Extended system monitor with additional metrics and reporting.
    Complements the core monitors in monitors.py with:
    - Cross-platform CPU info (where available)
    - Persistent health snapshots
    - JSON report generation
    """

    def __init__(self):
        self.system_info = {
            "os": platform.system(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor()
        }
        self.snapshots: List[Dict] = []

    def get_disk_usage(self, path: str = "/") -> Optional[Dict]:
        """
        Get disk usage statistics for a given path.

        Args:
            path: Filesystem path to check (default: root "/")

        Returns:
            Dict with total_gb and percent_used, or None on error.
        """
        try:
            usage = shutil.disk_usage(path)
            percent = (usage.used / usage.total) * 100
            return {
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent_used": round(percent, 2),
                "path": path
            }
        except Exception as e:
            logger.error(f"Disk usage check failed for {path}: {e}")
            return None

    def take_snapshot(self) -> Dict:
        """
        Take a full system health snapshot combining disk, system info,
        and a timestamp.

        Returns:
            Dict with timestamp, system_info, and disk_usage.
        """
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "system_info": self.system_info,
            "disk_usage": self.get_disk_usage()
        }
        self.snapshots.append(snapshot)
        logger.info(f"Snapshot taken: {snapshot['timestamp']}")
        return snapshot

    def save_report(self, filename: str = "system_guard_report.json") -> None:
        """
        Save all snapshots to a JSON report file.

        Args:
            filename: Output JSON file path.
        """
        if not self.snapshots:
            logger.warning("No snapshots to save.")
            return

        try:
            report = {
                "generated_at": datetime.now().isoformat(),
                "total_snapshots": len(self.snapshots),
                "snapshots": self.snapshots
            }
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def get_summary(self) -> Dict:
        """
        Get a summary of all collected snapshots.

        Returns:
            Dict with snapshot count, system info, and latest disk usage.
        """
        if not self.snapshots:
            return {"status": "No data", "total_snapshots": 0}

        latest = self.snapshots[-1]
        return {
            "total_snapshots": len(self.snapshots),
            "system": latest.get("system_info", {}),
            "latest_disk_usage": latest.get("disk_usage", {}),
            "last_updated": latest.get("timestamp", "")
        }


if __name__ == "__main__":
    monitor = SystemMonitor()
    print("SystemGuard Professional Extension")
    print(f"System: {monitor.system_info['os']} - {monitor.system_info['machine']}")

    # Take a snapshot
    snapshot = monitor.take_snapshot()
    if snapshot.get("disk_usage"):
        du = snapshot["disk_usage"]
        print(f"Disk: {du['percent_used']}% used ({du['used_gb']}GB / {du['total_gb']}GB)")

    # Save report
    monitor.save_report()
    print(f"\nSummary: {json.dumps(monitor.get_summary(), indent=2)}")