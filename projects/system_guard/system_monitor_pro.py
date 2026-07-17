import shutil
import logging
import platform

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SystemMonitor:
    def __init__(self):
        self.system_info = {"os": platform.system(), "version": platform.version()}

    def get_disk_usage(self, path="/"):
        try:
            usage = shutil.disk_usage(path)
            percent = (usage.used / usage.total) * 100
            return {"total_gb": usage.total // (2**30), "percent": round(percent, 2)}
        except Exception as e:
            logger.error(f"Error: {e}")
            return None

if __name__ == "__main__":
    monitor = SystemMonitor()
    logger.info("SystemGuard V2 Active")
    print(monitor.get_disk_usage())
