import os
import shutil
import subprocess
import socket
import logging
from abc import ABC, abstractmethod

# Configure logging for Grok Standards
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SystemGuard")

class BaseMonitor(ABC):
    """Abstract base class for system monitors."""
    @abstractmethod
    def check(self):
        """Perform the system check and return data."""
        pass

class DiskMonitor(BaseMonitor):
    """Monitors disk usage for a specific path."""
    def __init__(self, path="/", threshold=90.0):
        self.path = path
        self.threshold = threshold

    def check(self):
        try:
            usage = shutil.disk_usage(self.path)
            percent_used = (usage.used / usage.total) * 100
            status = "Healthy" if percent_used < self.threshold else "Warning"
            
            data = {
                "status": status,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent_used": round(percent_used, 2)
            }
            if status == "Warning":
                logger.warning(f"Disk usage high on {self.path}: {percent_used}%")
            return data
        except Exception as e:
            logger.error(f"Disk check failed: {e}")
            return {"error": str(e)}

class NetworkMonitor(BaseMonitor):
    """Monitors network connectivity via socket connection."""
    def __init__(self, host="8.8.8.8", port=53, timeout=3):
        self.host = host
        self.port = port
        self.timeout = timeout

    def check(self):
        try:
            socket.setdefaulttimeout(self.timeout)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
            return {"status": "Online", "target": f"{self.host}:{self.port}"}
        except (socket.error, socket.timeout) as e:
            logger.info(f"Host {self.host} unreachable: {e}")
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
        logger.error("Load average requested on unsupported system")
        return {"error": "Load average not available on this system"}
