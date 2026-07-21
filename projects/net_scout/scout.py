import socket
import logging
import concurrent.futures
from typing import List, Tuple

# Setup logging for Grok Standards
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NetScout")

class NetScout:
    """
    NetScout: A fast, multithreaded port scanner for network diagnostics.
    Follows OOP principles and provides professional-grade logging.
    """
    
    def __init__(self, target: str, timeout: float = 1.0):
        self.target = target
        self.timeout = timeout
        try:
            self.ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.ip = None
            logger.error(f"Could not resolve host: {target}")

    def scan_port(self, port: int) -> Tuple[int, bool]:
        """
        Attempts to connect to a specific port on the target.
        Returns a tuple of (port, status).
        """
        if not self.ip:
            return port, False
            
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))
                return port, result == 0
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return port, False

    def scan_range(self, start_port: int, end_port: int, workers: int = 100) -> List[int]:
        """
        Scans a range of ports using a thread pool for efficiency.
        """
        if not self.ip:
            logger.error("Scan aborted: Invalid target.")
            return []

        open_ports = []
        ports = range(start_port, end_port + 1)
        
        logger.info(f"Starting scan on {self.target} ({self.ip}) for ports {start_port}-{end_port}...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    logger.info(f"Port {port} is OPEN")
        
        return sorted(open_ports)

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    scout = NetScout(target)
    found = scout.scan_range(20, 1024)
    print(f"\nScan complete. Open ports: {found}")
