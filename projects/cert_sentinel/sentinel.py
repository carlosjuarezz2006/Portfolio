"""
CertSentinel: A professional SSL/TLS certificate monitoring tool.
=================================================================
Monitors SSL/TLS certificate status, expiration, issuer info, and
chain validation. Supports bulk concurrent checking, structured
reporting, and configurable alert thresholds.

Grok Build Standards:
- Cryptographic Security: Uses Python's ssl module with secure defaults
- OOP: Clean separation with CertSentinel, CertInfo, CertReport
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import ssl
import socket
import datetime
import logging
import json
import time
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import timezone

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("CertSentinel")

# Alert thresholds in days
DEFAULT_WARN_DAYS = 30
DEFAULT_CRITICAL_DAYS = 14


@dataclass
class CertInfo:
    """Structured certificate information from a domain check."""
    domain: str
    port: int
    expires: str
    days_left: int
    issuer: str
    subject: str
    serial_number: str
    is_valid: bool
    error: Optional[str] = None
    timestamp: float = 0.0


@dataclass
class CertReport:
    """Aggregated report from a bulk certificate check."""
    total_domains: int
    healthy: int
    warning: int
    critical: int
    expired: int
    errors: int
    details: List[Dict]
    timestamp: float


class CertSentinel:
    """
    Professional SSL/TLS certificate monitoring tool.

    Monitors domain certificate health with configurable ports,
    timeouts, and alert thresholds. Supports bulk concurrent checking
    and structured JSON reporting.

    Features:
    - Certificate expiration tracking with day count
    - Issuer and subject identification
    - Serial number extraction
    - Concurrent bulk checking via thread pool
    - Configurable alert thresholds (warning/critical)
    - Structured reports with JSON export
    - Chain of trust validation

    Usage:
        sentinel = CertSentinel(timeout=10)
        info = sentinel.get_cert_info("example.com")
        report = sentinel.bulk_check(["example.com", "github.com"])
    """

    def __init__(
        self,
        timeout: int = 10,
        warn_days: int = DEFAULT_WARN_DAYS,
        critical_days: int = DEFAULT_CRITICAL_DAYS,
        workers: int = 10
    ):
        """
        Initialize CertSentinel.

        Args:
            timeout: Connection timeout in seconds.
            warn_days: Days before expiry to trigger warning status.
            critical_days: Days before expiry to trigger critical status.
            workers: Number of concurrent workers for bulk checks.
        """
        self.timeout = timeout
        self.warn_days = warn_days
        self.critical_days = critical_days
        self.workers = workers
        self.context = ssl.create_default_context()
        self.history: List[CertInfo] = []
        logger.info(
            "CertSentinel initialized: timeout=%ds, warn=%dd, critical=%dd",
            timeout, warn_days, critical_days
        )

    def get_cert_info(self, domain: str, port: int = 443) -> Optional[CertInfo]:
        """
        Retrieve SSL certificate information for a domain.

        Connects to the domain:port, performs TLS handshake, and
        extracts certificate metadata.

        Args:
            domain: Domain name to check (e.g., "example.com").
            port: Port number (default: 443).

        Returns:
            CertInfo object with certificate details, or None on failure.
        """
        try:
            with socket.create_connection(
                (domain, port), timeout=self.timeout
            ) as sock:
                with self.context.wrap_socket(
                    sock, server_hostname=domain
                ) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return CertInfo(
                            domain=domain, port=port,
                            expires="", days_left=0,
                            issuer="", subject="",
                            serial_number="", is_valid=False,
                            error="No certificate returned",
                            timestamp=time.time()
                        )
                    return self._parse_cert(cert, domain, port)

        except socket.timeout:
            logger.warning("Timeout connecting to %s:%d", domain, port)
            return CertInfo(
                domain=domain, port=port,
                expires="", days_left=0,
                issuer="", subject="", serial_number="",
                is_valid=False, error="Connection timeout",
                timestamp=time.time()
            )
        except socket.gaierror:
            logger.warning("DNS resolution failed for %s", domain)
            return CertInfo(
                domain=domain, port=port,
                expires="", days_left=0,
                issuer="", subject="", serial_number="",
                is_valid=False, error="DNS resolution failed",
                timestamp=time.time()
            )
        except ssl.SSLError as e:
            logger.warning("SSL error for %s: %s", domain, e)
            return CertInfo(
                domain=domain, port=port,
                expires="", days_left=0,
                issuer="", subject="", serial_number="",
                is_valid=False, error=f"SSL error: {str(e)}",
                timestamp=time.time()
            )
        except OSError as e:
            logger.warning("Connection error for %s: %s", domain, e)
            return CertInfo(
                domain=domain, port=port,
                expires="", days_left=0,
                issuer="", subject="", serial_number="",
                is_valid=False, error=f"Connection error: {str(e)}",
                timestamp=time.time()
            )

    def _parse_cert(self, cert: Dict, domain: str, port: int) -> CertInfo:
        """
        Parse raw certificate data into a structured CertInfo object.

        Args:
            cert: Raw certificate dictionary from getpeercert().
            domain: The domain being checked.
            port: The port being checked.

        Returns:
            CertInfo with parsed certificate data.
        """
        # Parse expiration date
        expire_str = cert.get("notAfter", "")
        days_left = 0
        expires = ""
        is_valid = False

        if expire_str:
            try:
                expire_date = datetime.datetime.strptime(
                    expire_str, "%b %d %H:%M:%S %Y %Z"
                )
                now = datetime.datetime.utcnow()
                days_left = (expire_date - now).days
                expires = expire_date.strftime("%Y-%m-%d")
                is_valid = days_left > 0
            except ValueError:
                logger.warning("Could not parse expiration date: %s", expire_str)

        # Parse issuer
        issuer = "Unknown"
        try:
            issuer_data = dict(x[0] for x in cert.get("issuer", []))
            issuer = issuer_data.get("organizationName", "Unknown")
        except (ValueError, TypeError, IndexError):
            pass

        # Parse subject
        subject = "Unknown"
        try:
            subject_data = dict(x[0] for x in cert.get("subject", []))
            subject = subject_data.get("commonName", "Unknown")
        except (ValueError, TypeError, IndexError):
            pass

        # Serial number
        serial_number = cert.get("serialNumber", "")

        info = CertInfo(
            domain=domain,
            port=port,
            expires=expires,
            days_left=days_left,
            issuer=issuer,
            subject=subject,
            serial_number=serial_number,
            is_valid=is_valid,
            timestamp=time.time()
        )
        self.history.append(info)
        return info

    def check_health(self, domain: str, port: int = 443) -> str:
        """
        Returns a human-readable health status string.

        Color-coded status:
        - 🟢 HEALTHY: More than warn_days until expiry
        - 🟡 WARNING: Between critical_days and warn_days
        - 🟠 CRITICAL: Less than critical_days but not expired
        - 🔴 EXPIRED: Certificate has expired

        Args:
            domain: Domain name to check.
            port: Port number (default: 443).

        Returns:
            Formatted health status string.
        """
        info = self.get_cert_info(domain, port)
        if not info or info.error:
            return f"🔴 ERROR: Could not retrieve certificate for {domain}."

        if info.days_left < 0:
            return (
                f"🔴 EXPIRED: Certificate for {domain} expired "
                f"{abs(info.days_left)} days ago ({info.expires})."
            )
        elif info.days_left <= self.critical_days:
            return (
                f"🟠 CRITICAL: Certificate for {domain} expires "
                f"in {info.days_left} days ({info.expires})."
            )
        elif info.days_left <= self.warn_days:
            return (
                f"🟡 WARNING: Certificate for {domain} expires "
                f"in {info.days_left} days ({info.expires})."
            )
        else:
            return (
                f"🟢 HEALTHY: Certificate for {domain} expires "
                f"in {info.days_left} days ({info.expires})."
            )

    def get_status(self, info: CertInfo) -> str:
        """
        Return a machine-readable status label for a CertInfo object.

        Args:
            info: CertInfo object to evaluate.

        Returns:
            Status string: "healthy", "warning", "critical", "expired", or "error".
        """
        if info.error:
            return "error"
        if info.days_left < 0:
            return "expired"
        if info.days_left <= self.critical_days:
            return "critical"
        if info.days_left <= self.warn_days:
            return "warning"
        return "healthy"

    def bulk_check(
        self,
        domains: List[str],
        port: int = 443
    ) -> CertReport:
        """
        Perform concurrent health checks on multiple domains.

        Uses a thread pool for parallel certificate checks.

        Args:
            domains: List of domain names to check.
            port: Port number for all domains (default: 443).

        Returns:
            CertReport with aggregated results and statistics.
        """
        start_time = time.time()
        logger.info(
            "Bulk checking %d domains (workers=%d)...",
            len(domains), self.workers
        )

        results: List[CertInfo] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:
            future_map = {
                executor.submit(self.get_cert_info, domain, port): domain
                for domain in domains
            }
            for future in concurrent.futures.as_completed(future_map):
                result = future.result()
                if result:
                    results.append(result)

        # Aggregate statistics
        healthy = sum(1 for r in results if self.get_status(r) == "healthy")
        warning_count = sum(1 for r in results if self.get_status(r) == "warning")
        critical = sum(1 for r in results if self.get_status(r) == "critical")
        expired = sum(1 for r in results if self.get_status(r) == "expired")
        errors = sum(1 for r in results if self.get_status(r) == "error")

        details = []
        for r in sorted(results, key=lambda x: x.days_left):
            d = asdict(r)
            d["status"] = self.get_status(r)
            details.append(d)

        report = CertReport(
            total_domains=len(domains),
            healthy=healthy,
            warning=warning_count,
            critical=critical,
            expired=expired,
            errors=errors,
            details=details,
            timestamp=time.time()
        )

        logger.info(
            "Bulk check complete: %d healthy, %d warning, %d critical, "
            "%d expired, %d errors (%.2fs)",
            healthy, warning_count, critical, expired, errors,
            time.time() - start_time
        )
        return report

    def get_summary(self) -> Dict:
        """
        Get a summary of all certificate checks in the current session.

        Returns:
            Dictionary with summary statistics.
        """
        total = len(self.history)
        if total == 0:
            return {"status": "No data", "total_checks": 0}

        statuses = [self.get_status(h) for h in self.history]
        return {
            "status": "active",
            "total_checks": total,
            "healthy": statuses.count("healthy"),
            "warning": statuses.count("warning"),
            "critical": statuses.count("critical"),
            "expired": statuses.count("expired"),
            "errors": statuses.count("error"),
            "last_check": asdict(self.history[-1]) if self.history else None,
            "domains_checked": list(set(h.domain for h in self.history))
        }

    def save_report(self, filename: str = "cert_report.json") -> str:
        """
        Save the current session history to a JSON file.

        Args:
            filename: Output filename.

        Returns:
            Path to the saved file.
        """
        data = {
            "summary": self.get_summary(),
            "checks": [
                {**asdict(h), "status": self.get_status(h)}
                for h in self.history
            ],
            "generated_at": datetime.datetime.now(timezone.utc).isoformat()
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Report saved to %s", filename)
        return filename


if __name__ == "__main__":
    sentinel = CertSentinel()

    # Single domain check
    domain = "google.com"
    print(f"Checking {domain}...")
    print(sentinel.check_health(domain))

    # Get structured info
    info = sentinel.get_cert_info(domain)
    if info:
        print(f"  Issuer: {info.issuer}")
        print(f"  Subject: {info.subject}")
        print(f"  Expires: {info.expires}")
        print(f"  Days left: {info.days_left}")

    # Bulk check
    domains = ["google.com", "github.com", "stackoverflow.com"]
    print(f"\nBulk checking {len(domains)} domains...")
    report = sentinel.bulk_check(domains)
    print(f"  Healthy: {report.healthy}")
    print(f"  Warning: {report.warning}")
    print(f"  Critical: {report.critical}")
    print(f"  Expired: {report.expired}")
    print(f"  Errors: {report.errors}")

    # Save report
    sentinel.save_report()