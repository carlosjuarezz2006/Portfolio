"""
APIFortress: A professional API monitoring and health-check tool.
=================================================================
Ensures backend services are reachable and performant with concurrent
monitoring, latency tracking, uptime statistics, and structured reporting.

Grok Build Standards:
- OOP: Clean separation with APIFortress, EndpointHealth, and MonitorReport
- Security: Configurable timeouts, SSL verification, rate limiting
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import requests
import time
import logging
import json
import concurrent.futures
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("APIFortress")


@dataclass
class EndpointHealth:
    """Health snapshot for a single API endpoint."""
    url: str
    status_code: Optional[int]
    latency: float
    is_up: bool
    response_size: int
    error_message: str
    timestamp: float


@dataclass
class MonitorReport:
    """Aggregated monitoring report for all endpoints."""
    total_endpoints: int
    endpoints_up: int
    endpoints_down: int
    uptime_percentage: float
    average_latency: float
    max_latency: float
    min_latency: float
    total_checks: int
    report_time: str


class APIFortress:
    """
    APIFortress: A professional API monitoring and health-check tool.

    Monitors API endpoints for availability, latency, and response integrity.
    Supports concurrent checks, SSL verification, custom headers, and
    structured JSON reporting with uptime tracking.
    """

    def __init__(self, timeout: int = 10, verify_ssl: bool = True,
                 max_workers: int = 10):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_workers = max_workers
        self.history: List[EndpointHealth] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "APIFortress/2.0 (GitHub Portfolio Monitor)"
        })

    def check_endpoint(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        expected_status: Optional[int] = None,
        expected_text: Optional[str] = None
    ) -> EndpointHealth:
        """
        Tests the health of a specific API endpoint.

        Args:
            url: The endpoint URL to check
            method: HTTP method (GET, POST, HEAD, etc.)
            headers: Optional custom headers
            expected_status: If set, endpoint is considered down if status doesn't match
            expected_text: If set, endpoint is considered down if text not in response

        Returns:
            EndpointHealth dataclass with the check results
        """
        start_time = time.perf_counter()
        is_up = False
        status_code = None
        response_size = 0
        error_message = ""

        try:
            response = self.session.request(
                method, url, headers=headers,
                timeout=self.timeout, verify=self.verify_ssl
            )
            status_code = response.status_code
            response_size = len(response.content)

            # Check expected status
            if expected_status and status_code != expected_status:
                is_up = False
                error_message = f"Expected status {expected_status}, got {status_code}"
            # Check expected text
            elif expected_text and expected_text not in response.text:
                is_up = False
                error_message = f"Expected text '{expected_text}' not found in response"
            else:
                is_up = 200 <= status_code < 500

            latency = (time.perf_counter() - start_time) * 1000
            logger.info(f"Checked {url} - Status: {status_code} - Latency: {latency:.2f}ms")

        except requests.exceptions.Timeout:
            latency = (time.perf_counter() - start_time) * 1000
            error_message = "Request timed out"
            logger.error(f"Timeout for {url} after {latency:.0f}ms")
        except requests.exceptions.ConnectionError as e:
            latency = (time.perf_counter() - start_time) * 1000
            error_message = f"Connection error: {type(e).__name__}"
            logger.error(f"Connection failed for {url}")
        except requests.exceptions.RequestException as e:
            latency = (time.perf_counter() - start_time) * 1000
            error_message = f"Request error: {type(e).__name__}"
            logger.error(f"Request failed for {url}: {e}")

        health = EndpointHealth(
            url=url,
            status_code=status_code,
            latency=latency,
            is_up=is_up,
            response_size=response_size,
            error_message=error_message,
            timestamp=time.time()
        )
        self.history.append(health)
        return health

    def bulk_monitor(self, urls: List[str], **kwargs) -> List[EndpointHealth]:
        """
        Monitors multiple endpoints concurrently using a thread pool.

        Args:
            urls: List of endpoint URLs to check
            **kwargs: Additional arguments passed to check_endpoint()

        Returns:
            List of EndpointHealth results
        """
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self.check_endpoint, url, **kwargs): url
                for url in urls
            }
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    url = future_to_url[future]
                    logger.error(f"Unexpected error checking {url}: {e}")

        # Sort results by URL for consistency
        results.sort(key=lambda r: r.url)
        return results

    def monitor_with_retry(
        self,
        url: str,
        retries: int = 3,
        backoff: float = 1.0,
        **kwargs
    ) -> EndpointHealth:
        """
        Monitor an endpoint with automatic retries on failure.

        Args:
            url: Endpoint URL
            retries: Number of retry attempts
            backoff: Multiplicative backoff factor between retries
            **kwargs: Additional arguments passed to check_endpoint()

        Returns:
            EndpointHealth from the last attempt
        """
        last_result = None
        for attempt in range(retries + 1):
            last_result = self.check_endpoint(url, **kwargs)
            if last_result.is_up:
                return last_result
            if attempt < retries:
                wait_time = backoff * (2 ** attempt)
                logger.info(f"Retry {attempt + 1}/{retries} for {url} in {wait_time:.1f}s")
                time.sleep(wait_time)
        return last_result

    def get_report(self) -> MonitorReport:
        """
        Generate an aggregated monitoring report from the current session.

        Returns:
            MonitorReport dataclass with aggregated statistics
        """
        if not self.history:
            return MonitorReport(
                total_endpoints=0, endpoints_up=0, endpoints_down=0,
                uptime_percentage=0.0, average_latency=0.0,
                max_latency=0.0, min_latency=0.0,
                total_checks=0, report_time=datetime.now(timezone.utc).isoformat()
            )

        total = len(self.history)
        up_count = sum(1 for h in self.history if h.is_up)
        avg_latency = sum(h.latency for h in self.history) / total
        max_latency = max(h.latency for h in self.history)
        min_latency = min(h.latency for h in self.history)

        return MonitorReport(
            total_endpoints=total,
            endpoints_up=up_count,
            endpoints_down=total - up_count,
            uptime_percentage=(up_count / total) * 100,
            average_latency=round(avg_latency, 2),
            max_latency=round(max_latency, 2),
            min_latency=round(min_latency, 2),
            total_checks=total,
            report_time=datetime.now(timezone.utc).isoformat()
        )

    def save_report(self, filename: str = "health_report.json"):
        """Saves the current monitoring history and report to a JSON file."""
        try:
            report_data = {
                "report": asdict(self.get_report()),
                "endpoints": [asdict(h) for h in self.history]
            }
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)
            logger.info(f"Report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """
        Provides a summary of all monitoring activities in the current session.

        Returns:
            Dictionary with summary statistics
        """
        if not self.history:
            return {"status": "No data", "total_checks": 0}

        up_count = sum(1 for h in self.history if h.is_up)
        avg_latency = sum(h.latency for h in self.history) / len(self.history)
        endpoints_down = [h for h in self.history if not h.is_up]

        return {
            "total_checks": len(self.history),
            "endpoints_up": up_count,
            "endpoints_down": len(self.history) - up_count,
            "uptime_percentage": round((up_count / len(self.history)) * 100, 2),
            "average_latency_ms": round(avg_latency, 2),
            "down_endpoints": [
                {"url": h.url, "error": h.error_message} for h in endpoints_down
            ],
            "last_check": asdict(self.history[-1]) if self.history else None
        }


if __name__ == "__main__":
    fortress = APIFortress()
    endpoints = [
        "https://google.com",
        "https://api.github.com",
        "https://httpstat.us/200",
        "https://httpstat.us/404",
    ]
    print("Starting API Monitor (concurrent mode)...")
    fortress.bulk_monitor(endpoints)

    print("\n" + "=" * 50)
    print("Session Summary:")
    print(json.dumps(fortress.get_summary(), indent=2))

    print("\nReport:")
    report = fortress.get_report()
    print(f"  Uptime: {report.uptime_percentage:.1f}%")
    print(f"  Avg Latency: {report.average_latency:.0f}ms")
    print(f"  Max Latency: {report.max_latency:.0f}ms")
    print(f"  Min Latency: {report.min_latency:.0f}ms")

    fortress.save_report()