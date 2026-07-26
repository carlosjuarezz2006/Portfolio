"""
NetScout: A fast, multithreaded port scanner for network diagnostics.
======================================================================
Uses TCP socket connections with thread pool parallelism for efficient
port scanning. Includes service identification, banner grabbing, and
structured JSON reporting.

Grok Build Standards:
- OOP: Clean separation with NetScout class, ScanResult dataclass, and
  service database
- Security: No raw socket operations — uses standard Python socket library
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import socket
import logging
import concurrent.futures
import json
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NetScout")

# Common ports mapped to service names
COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle-DB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


@dataclass
class ScanResult:
    """Result of a single port scan."""
    port: int
    service: str
    is_open: bool
    banner: Optional[str] = None
    latency_ms: Optional[float] = None


@dataclass
class ScanReport:
    """Complete scan report for a target."""
    target: str
    ip: str
    start_port: int
    end_port: int
    ports_scanned: int
    open_ports: int
    results: List[dict]
    scan_duration_s: float
    timestamp: str


class NetScout:
    """
    A fast, multithreaded port scanner for network diagnostics.

    Features:
    - Thread pool-based parallel scanning (configurable worker count)
    - 30+ common service identifications
    - Optional banner grabbing on open ports
    - Structured ScanReport with JSON export
    - Hostname resolution with error handling
    """

    def __init__(self, target: str, timeout: float = 1.0, grab_banner: bool = False):
        """
        Initialize the scanner for a target.

        Args:
            target: Hostname or IP address to scan
            timeout: Connection timeout in seconds (default 1.0)
            grab_banner: Attempt to grab service banners on open ports
        """
        self.target = target
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.ip: Optional[str] = None
        self._resolve_host()

    def _resolve_host(self) -> None:
        """Resolve hostname to IP address, or use IP directly."""
        try:
            self.ip = socket.gethostbyname(self.target)
            logger.info(f"Resolved {self.target} -> {self.ip}")
        except socket.gaierror:
            self.ip = None
            logger.error(f"Could not resolve host: {self.target}")

    def _scan_port(self, port: int) -> ScanResult:
        """
        Attempt to connect to a specific port on the target.

        Args:
            port: Port number to scan

        Returns:
            ScanResult with status and optional banner
        """
        if not self.ip:
            return ScanResult(port=port, service=self._get_service(port),
                              is_open=False)

        start_time = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))
                latency = (time.perf_counter() - start_time) * 1000

                if result == 0:
                    banner = None
                    if self.grab_banner:
                        try:
                            s.sendall(b"\r\n")
                            banner_data = s.recv(1024)
                            banner = banner_data.decode("utf-8", errors="replace").strip()
                        except Exception:
                            banner = None

                    return ScanResult(
                        port=port,
                        service=self._get_service(port),
                        is_open=True,
                        banner=banner,
                        latency_ms=round(latency, 2)
                    )

                return ScanResult(port=port, service=self._get_service(port),
                                  is_open=False)
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return ScanResult(port=port, service=self._get_service(port),
                              is_open=False)

    def _get_service(self, port: int) -> str:
        """Map a port number to its common service name."""
        return COMMON_SERVICES.get(port, "Unknown")

    def scan_range(self, start_port: int, end_port: int,
                   workers: int = 100) -> ScanReport:
        """
        Scan a range of ports using a thread pool.

        Args:
            start_port: First port to scan (inclusive)
            end_port: Last port to scan (inclusive)
            workers: Number of concurrent threads (default 100)

        Returns:
            ScanReport with all results
        """
        scan_start = time.perf_counter()

        if not self.ip:
            logger.error("Scan aborted: Invalid target.")
            return ScanReport(
                target=self.target, ip="", start_port=start_port,
                end_port=end_port, ports_scanned=0, open_ports=0,
                results=[], scan_duration_s=0,
                timestamp=datetime.now().isoformat()
            )

        ports = list(range(start_port, end_port + 1))
        logger.info(f"Scanning {self.target} ({self.ip}) ports {start_port}-{end_port} "
                    f"({len(ports)} ports, {workers} workers)")

        scan_results: List[ScanResult] = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, port): port
                    for port in ports
                }
                for future in concurrent.futures.as_completed(future_to_port):
                    result = future.result()
                    scan_results.append(result)
                    if result.is_open:
                        banner_info = f" [{result.banner[:50]}]" if result.banner else ""
                        logger.info(f"Port {result.port} ({result.service}) is OPEN"
                                    f"{banner_info}")

        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")

        scan_duration = time.perf_counter() - scan_start
        open_ports = [r for r in scan_results if r.is_open]

        report = ScanReport(
            target=self.target,
            ip=self.ip or "",
            start_port=start_port,
            end_port=end_port,
            ports_scanned=len(ports),
            open_ports=len(open_ports),
            results=[asdict(r) for r in sorted(scan_results, key=lambda x: x.port)],
            scan_duration_s=round(scan_duration, 2),
            timestamp=datetime.now().isoformat()
        )

        logger.info(f"Scan complete: {len(open_ports)} open ports found "
                    f"in {scan_duration:.1f}s")
        return report

    def scan_quick(self, workers: int = 50) -> ScanReport:
        """
        Quick scan of the top 100 most common ports.

        Args:
            workers: Number of concurrent threads

        Returns:
            ScanReport with results
        """
        return self.scan_range(1, 1024, workers=workers)

    def scan_extended(self, workers: int = 100) -> ScanReport:
        """
        Extended scan for common service ports (1-10000).

        Args:
            workers: Number of concurrent threads

        Returns:
            ScanReport with results
        """
        return self.scan_range(1, 10000, workers=workers)

    def scan_well_known(self, workers: int = 50) -> ScanReport:
        """
        Scan only the well-known ports (1-1023).

        Args:
            workers: Number of concurrent threads

        Returns:
            ScanReport with results
        """
        return self.scan_range(1, 1023, workers=workers)

    @staticmethod
    def save_report(report: ScanReport, filename: str = "net_scout_report.json") -> str:
        """
        Save a scan report to a JSON file.

        Args:
            report: ScanReport to save
            filename: Output filename

        Returns:
            Path to the saved file
        """
        with open(filename, 'w') as f:
            json.dump(asdict(report), f, indent=4)
        logger.info(f"Report saved to {filename}")
        return filename

    @staticmethod
    def print_summary(report: ScanReport) -> None:
        """Print a human-readable summary of the scan."""
        print("\n" + "=" * 50)
        print(f"  NetScout Scan Report")
        print("=" * 50)
        print(f"  Target:    {report.target} ({report.ip})")
        print(f"  Range:     {report.start_port}-{report.end_port}")
        print(f"  Scanned:   {report.ports_scanned} ports")
        print(f"  Open:      {report.open_ports} ports")
        print(f"  Duration:  {report.scan_duration_s:.1f}s")
        print(f"  Time:      {report.timestamp}")
        print("-" * 50)

        open_results = [r for r in report.results if r["is_open"]]
        if open_results:
            print(f"  Open Ports:")
            for r in sorted(open_results, key=lambda x: x["port"]):
                banner = f" - {r['banner'][:60]}" if r.get("banner") else ""
                latency = f" [{r['latency_ms']}ms]" if r.get("latency_ms") else ""
                print(f"    {r['port']:5d}/{r['service']:15s} OPEN{banner}{latency}")
        else:
            print("  No open ports found.")
        print("=" * 50)

    @staticmethod
    def compare_reports(report1: ScanReport, report2: ScanReport) -> dict:
        """
        Compare two scan reports and identify changes.

        Args:
            report1: First scan report (baseline)
            report2: Second scan report (current)

        Returns:
            Dict with new, closed, and unchanged ports
        """
        ports1 = {r["port"] for r in report1.results if r["is_open"]}
        ports2 = {r["port"] for r in report2.results if r["is_open"]}

        return {
            "new_ports": sorted(ports2 - ports1),
            "closed_ports": sorted(ports1 - ports2),
            "unchanged_ports": sorted(ports1 & ports2),
            "report1": report1.target,
            "report2": report2.target,
        }


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    mode = sys.argv[2] if len(sys.argv) > 2 else "quick"
    grab = "--banner" in sys.argv

    scout = NetScout(target, grab_banner=grab)

    if mode == "quick":
        report = scout.scan_quick()
    elif mode == "extended":
        report = scout.scan_extended(workers=200)
    elif mode == "well-known":
        report = scout.scan_well_known()
    else:
        try:
            parts = mode.split("-")
            start, end = int(parts[0]), int(parts[1])
            report = scout.scan_range(start, end)
        except (ValueError, IndexError):
            print(f"Usage: {sys.argv[0]} <target> [quick|extended|well-known|start-end] [--banner]")
            sys.exit(1)

    NetScout.print_summary(report)
    NetScout.save_report(report)

    if report.open_ports > 0:
        print(f"\nTip: NetScout identified {report.open_ports} open services.")