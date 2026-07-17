import os
import shutil
import subprocess
import socket
from abc import ABC, abstractmethod

class BaseMonitor(ABC):
    """Abstract base class for system monitors."""
    @abstractmethod
    def check(self):
        """Perform the system check and return data."""
        pass

class DiskMonitor(BaseMonitor):
    """Monitors disk usage for a specific path."""
    def __init__(self, path="/"):
        self.path = path

    def check(self):
        try:
            usage = shutil.disk_usage(self.path)
            percent_used = (usage.used / usage.total) * 100
            return {
                "status": "Healthy" if percent_used < 90 else "Warning",
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent_used": round(percent_used, 2)
            }
        except Exception as e:
            return {"error": str(e)}

class NetworkMonitor(BaseMonitor):
    """Monitors network connectivity via socket connection."""
    def __init__(self, host="8.8.8.8", port=53):
        self.host = host
        self.port = port

    def check(self):
        try:
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((self.host, self.port))
            return {"status": "Online", "target": f"{self.host}:{self.port}"}
        except (socket.error, socket.timeout):
            return {"status": "Offline", "target": f"{self.host}:{self.port}"}

class LoadMonitor(BaseMonitor):
    """Monitors system load average."""
    def check(self):
        if hasattr(os, 'getloadavg'):
            load = os.getloadavg()
            return {
                "1min": load[0],
                "5min": load[1],
                "15min": load[2]
            }
        return {"error": "Load average not available on this system"}
