import requests
import re
import json
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("WebGlean")

@dataclass
class PageInsight:
    url: str
    status_code: int
    title: str
    description: str
    headings: Dict[str, int]
    links: Dict[str, int]
    images_without_alt: int
    load_time_ms: float
    has_favicon: bool
    has_viewport_meta: bool
    issues: List[str]
    timestamp: float

class WebGlean:
    """
    WebGlean: A web content extraction and validation tool.
    Fetches URLs, extracts structured metadata, and audits for basic
    SEO and accessibility issues.
    """
    
    def __init__(self, timeout: int = 10, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.session = requests.Session()
        if user_agent:
            self.session.headers.update({"User-Agent": user_agent})
        else:
            self.session.headers.update({
                "User-Agent": "WebGlean/1.0 (Portfolio Audit Tool; +https://github.com/carlosjuarezz2006/Portfolio)"
            })
        self.history: List[PageInsight] = []

    def _extract_meta(self, html: str, tag: str, attr: str) -> str:
        """Extract meta tag content by attribute name."""
        pattern = rf'<meta\s+[^>]*{attr}="([^"]+)"[^>]*content="([^"]+)"'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            # Try both orderings: name="..." content="..." or content="..." name="..."
            if match.group(1) == tag:
                return match.group(2)
        # Try reversed attribute order
        pattern = rf'<meta\s+[^>]*content="([^"]+)"[^>]*{attr}="([^"]+)"'
        match = re.search(pattern, html, re.IGNORECASE)
        if match and match.group(2) == tag:
            return match.group(1)
        return ""

    def _count_headings(self, html: str) -> Dict[str, int]:
        """Count all heading tags (h1-h6) in the HTML."""
        headings = {}
        for level in range(1, 7):
            pattern = rf'<h{level}[^>]*>'
            count = len(re.findall(pattern, html, re.IGNORECASE))
            headings[f"h{level}"] = count
        return headings

    def _find_links(self, html: str, base_url: str) -> Dict[str, int]:
        """Count internal vs external links."""
        internal = 0
        external = 0
        base_domain = urlparse(base_url).netloc
        
        for match in re.finditer(r'<a\s+[^>]*href="([^"]+)"', html, re.IGNORECASE):
            href = match.group(1)
            if href.startswith('#') or href.startswith('javascript:'):
                continue
            parsed = urlparse(href)
            if not parsed.netloc:
                internal += 1
            elif parsed.netloc == base_domain:
                internal += 1
            else:
                external += 1
        
        return {"internal": internal, "external": external}

    def _count_images_without_alt(self, html: str) -> int:
        """Count img tags that lack an alt attribute."""
        # Match img tags without alt attribute
        images_bad = len(re.findall(r'<img\s+[^>]*(?<!alt=)(?<!alt\s*=)(?<!alt\s*=\s*")[^>]*>', html, re.IGNORECASE))
        return images_bad

    def _check_has_favicon(self, html: str) -> bool:
        """Check if the page has a favicon link."""
        return bool(re.search(r'<link[^>]*rel=["\']?(?:icon|shortcut icon)["\']?', html, re.IGNORECASE))

    def _check_has_viewport(self, html: str) -> bool:
        """Check if the page has a viewport meta tag."""
        return bool(re.search(r'<meta[^>]*name=["\']viewport["\']', html, re.IGNORECASE))

    def glean(self, url: str) -> PageInsight:
        """
        Fetches a URL and extracts structured insights about the page.
        """
        import time
        start_time = time.perf_counter()
        issues: List[str] = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            load_time = (time.perf_counter() - start_time) * 1000
            html = response.text
            status_code = response.status_code
        except requests.exceptions.Timeout:
            load_time = (time.perf_counter() - start_time) * 1000
            insight = PageInsight(
                url=url, status_code=0, title="", description="",
                headings={}, links={}, images_without_alt=0,
                load_time_ms=load_time, has_favicon=False, has_viewport_meta=False,
                issues=["Request timed out"], timestamp=time.time()
            )
            self.history.append(insight)
            return insight
        except requests.exceptions.RequestException as e:
            load_time = (time.perf_counter() - start_time) * 1000
            insight = PageInsight(
                url=url, status_code=0, title="", description="",
                headings={}, links={}, images_without_alt=0,
                load_time_ms=load_time, has_favicon=False, has_viewport_meta=False,
                issues=[f"Request failed: {str(e)}"], timestamp=time.time()
            )
            self.history.append(insight)
            return insight

        # Extract title
        title_match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else ""
        if not title:
            issues.append("Missing <title> tag")

        # Extract description
        description = self._extract_meta(html, "description", "name")
        if not description:
            issues.append("Missing meta description")

        # Count headings
        headings = self._count_headings(html)
        if headings.get("h1", 0) == 0:
            issues.append("Missing <h1> heading")
        elif headings.get("h1", 0) > 1:
            issues.append(f"Multiple <h1> headings ({headings['h1']})")

        # Count links
        links = self._find_links(html, url)

        # Count images without alt
        images_without_alt = self._count_images_without_alt(html)
        if images_without_alt > 0:
            issues.append(f"{images_without_alt} image(s) missing alt text")

        # Favicon check
        has_favicon = self._check_has_favicon(html)
        if not has_favicon:
            issues.append("Missing favicon")

        # Viewport meta check
        has_viewport = self._check_has_viewport(html)
        if not has_viewport:
            issues.append("Missing viewport meta tag for mobile responsiveness")

        insight = PageInsight(
            url=url,
            status_code=status_code,
            title=title,
            description=description,
            headings=headings,
            links=links,
            images_without_alt=images_without_alt,
            load_time_ms=round(load_time, 2),
            has_favicon=has_favicon,
            has_viewport_meta=has_viewport,
            issues=issues,
            timestamp=time.time()
        )
        self.history.append(insight)
        logger.info(f"Gleaned {url} - {status_code} - {load_time:.0f}ms")
        return insight

    def bulk_glean(self, urls: List[str]) -> List[PageInsight]:
        """Glean multiple URLs and return all insights."""
        results = []
        for url in urls:
            results.append(self.glean(url))
        return results

    def save_audit(self, filename: str = "web_audit.json"):
        """Save gleaning history to a JSON file."""
        try:
            report = [asdict(i) for i in self.history]
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Audit saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save audit: {e}")

    def get_summary(self) -> Dict:
        """Get a summary of all gleaned pages."""
        total = len(self.history)
        if total == 0:
            return {"status": "No data"}
        
        up_count = sum(1 for h in self.history if 200 <= h.status_code < 400)
        avg_load = sum(h.load_time_ms for h in self.history) / total
        total_issues = sum(len(h.issues) for h in self.history)
        
        return {
            "total_pages": total,
            "healthy_pages": up_count,
            "average_load_ms": round(avg_load, 2),
            "total_issues_found": total_issues,
            "last_audit": asdict(self.history[-1])
        }


if __name__ == "__main__":
    gleaner = WebGlean()
    urls = [
        "https://github.com/carlosjuarezz2006/Portfolio",
        "https://google.com"
    ]
    print("Starting WebGlean audit...")
    gleaner.bulk_glean(urls)
    gleaner.save_audit()
    print("\nAudit Summary:")
    print(json.dumps(gleaner.get_summary(), indent=2))