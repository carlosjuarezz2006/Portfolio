import ssl
import socket
import datetime
import logging
from typing import Dict, Optional, List

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CertSentinel")

class CertSentinel:
    """
    CertSentinel: A tool to monitor SSL/TLS certificate status.
    Provides expiration dates and issuer information for domains.
    """
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.context = ssl.create_default_context()

    def get_cert_info(self, domain: str, port: int = 443) -> Optional[Dict]:
        """
        Retrieves SSL certificate information for a given domain.
        """
        try:
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with self.context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return self._parse_cert(cert)
        except Exception as e:
            logger.error(f"Failed to retrieve certificate for {domain}: {e}")
            return None

    def _parse_cert(self, cert: Dict) -> Dict:
        """
        Parses raw certificate data into a readable format.
        """
        # Expiration date format: 'Jul 20 12:00:00 2026 GMT'
        expire_str = cert.get('notAfter')
        expire_date = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
        
        days_to_expire = (expire_date - datetime.datetime.utcnow()).days
        
        issuer = dict(x[0] for x in cert.get('issuer'))
        
        return {
            "expires": expire_date.strftime('%Y-%m-%d'),
            "days_left": days_to_expire,
            "issuer": issuer.get('organizationName', 'Unknown'),
            "subject": dict(x[0] for x in cert.get('subject')).get('commonName', 'Unknown')
        }

    def check_health(self, domain: str) -> str:
        """
        Returns a health status string for the domain's certificate.
        """
        info = self.get_cert_info(domain)
        if not info:
            return "🔴 CRITICAL: Could not retrieve certificate."
        
        days = info['days_left']
        if days < 0:
            return f"🔴 EXPIRED: Certificate expired {abs(days)} days ago."
        elif days < 14:
            return f"🟠 WARNING: Certificate expires in {days} days."
        else:
            return f"🟢 HEALTHY: Certificate expires in {days} days."

    def bulk_check(self, domains: List[str]) -> Dict[str, str]:
        """
        Performs health checks on multiple domains.
        """
        results = {}
        for domain in domains:
            results[domain] = self.check_health(domain)
        return results

if __name__ == "__main__":
    sentinel = CertSentinel()
    domain = "google.com"
    print(f"Checking {domain}...")
    print(sentinel.check_health(domain))
    
    # Example of new bulk_check feature
    domains = ["google.com", "github.com", "invalid.test"]
    print("\nBulk Check Results:")
    for d, status in sentinel.bulk_check(domains).items():
        print(f"{d}: {status}")
