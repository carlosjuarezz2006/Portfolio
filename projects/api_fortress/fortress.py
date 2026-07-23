import requests
import time
import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("APIFortress")

@dataclass
class EndpointHealth:
    url: str
    status_code: Optional[int]
    latency: float
    is_up: bool
    timestamp: float

class APIFortress:
    """
    APIFortress: A professional API monitoring and health-check tool.
    Ensures backend services are reachable and performant.
    """
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.history: List[EndpointHealth] = []

    def check_endpoint(self, url: str, method: str = "GET", headers: Optional[Dict] = None) -> EndpointHealth:
        """
        Tests the health of a specific API endpoint.
        """
        start_time = time.perf_counter()
        is_up = False
        status_code = None
        
        try:
            response = requests.request(method, url, headers=headers, timeout=self.timeout)
            status_code = response.status_code
            is_up = 200 <= status_code < 400
            latency = (time.perf_counter() - start_time) * 1000
            logger.info(f"Checked {url} - Status: {status_code} - Latency: {latency:.2f}ms")
        except requests.exceptions.RequestException as e:
            latency = (time.perf_counter() - start_time) * 1000
            logger.error(f"Failed to reach {url}: {e}")
            is_up = False

        health = EndpointHealth(
            url=url,
            status_code=status_code,
            latency=latency,
            is_up=is_up,
            timestamp=time.time()
        )
        self.history.append(health)
        return health

    def bulk_monitor(self, urls: List[str]) -> List[EndpointHealth]:
        """
        Monitors a list of endpoints and returns their health status.
        """
        results = []
        for url in urls:
            results.append(self.check_endpoint(url))
        return results

    def save_report(self, filename: str = "health_report.json"):
        """Saves the current monitoring history to a JSON file."""
        try:
            report_data = [asdict(h) for h in self.history]
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)
            logger.info(f"Report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def get_summary(self) -> Dict:
        """
        Provides a summary of all monitoring activities in the current session.
        """
        total = len(self.history)
        if total == 0:
            return {"status": "No data"}
            
        up_count = sum(1 for h in self.history if h.is_up)
        avg_latency = sum(h.latency for h in self.history) / total
        
        return {
            "total_checks": total,
            "uptime_percentage": (up_count / total) * 100,
            "average_latency_ms": round(avg_latency, 2),
            "last_check": asdict(self.history[-1]) if self.history else None
        }

if __name__ == "__main__":
    fortress = APIFortress()
    endpoints = ["https://google.com", "https://api.github.com", "https://invalid.url.test"]
    print("Starting API Monitor...")
    fortress.bulk_monitor(endpoints)
    fortress.save_report()
    print("\nSession Summary:")
    print(fortress.get_summary())
