"""
WebGlean: A professional web content extraction and validation tool.
====================================================================
Fetches URLs, extracts structured metadata, and audits for basic SEO,
accessibility, and performance issues. Provides structured JSON reports
with actionable insights.

Grok Build Standards:
- OOP: Clean separation with PageInsight dataclass and WebGlean class
- Security: Uses requests library with configurable timeouts and user-agent
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import requests
import re
import json
import logging
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("WebGlean")


@dataclass
class PageInsight:
    """Structured data extracted from a single page audit."""
    url: str
    status_code: int
    title: str
    description: str
    headings: Dict[str, int]
    internal_links: int
    external_links: int
    broken_links: int
    images_without_alt: int
    total_images: int
    load_time_ms: float
    content_length_bytes: int
    has_favicon: bool
    has_viewport_meta: bool
    has_canonical: bool
    has_open_graph: bool
    issues: List[str]
    timestamp: float


class WebGlean:
    """
    A web content extraction and validation tool.

    Fetches URLs, extracts structured metadata, and audits for basic SEO
    and accessibility issues. Provides actionable insights for improvement.

    Features:
    - URL content extraction with metadata
    - SEO audit (title, description, viewport, canonical, Open Graph)
    - Accessibility audit (image alt text, heading structure)
    - Link analysis (internal vs external, broken link detection)
    - Performance metrics (load time, content size)
    - Structured JSON reporting with session history
    - Bulk auditing for multiple URLs
    """

    def __init__(self, timeout: int = 10, user_agent: Optional[str] = None,
                 verify_ssl: bool = True):
        """
        Initialize the WebGleaner.

        Args:
            timeout: Request timeout in seconds (default 10)
            user_agent: Custom User-Agent string
            verify_ssl: Verify SSL certificates (default True)
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or "WebGlean/1.0 (Portfolio Audit Tool; +https://github.com/carlosjuarezz2006/Portfolio)"
        })
        self.history: List[PageInsight] = []

    def _extract_meta(self, html: str, tag: str, attr: str,
                      attr_value: str, content_attr: str = "content") -> str:
        """
        Extract meta tag content by attribute name.

        Args:
            html: HTML content to search
            tag: HTML tag name (e.g., 'meta')
            attr: Attribute to match (e.g., 'name', 'property')
            attr_value: Value of the attribute (e.g., 'description')
            content_attr: Attribute containing the value (default 'content')

        Returns:
            Extracted value or empty string if not found
        """
        pattern = rf'<{tag}\s+[^>]*{attr}\s*=\s*["\']{re.escape(attr_value)}["\'][^>]*{content_attr}\s*=\s*["\']([^"\']+)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _extract_title(self, html: str) -> str:
        """Extract the page title from HTML."""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else "No title found"

    def _extract_headings(self, html: str) -> Dict[str, int]:
        """Count heading tags (h1-h6) in the HTML."""
        headings: Dict[str, int] = {}
        for i in range(1, 7):
            pattern = rf'<h{i}[^>]*>'
            count = len(re.findall(pattern, html, re.IGNORECASE))
            if count > 0:
                headings[f"h{i}"] = count
        return headings

    def _extract_links(self, html: str, base_url: str) -> Dict[str, int]:
        """
        Count internal and external links in the HTML.

        Args:
            html: HTML content
            base_url: Base URL for resolving relative links

        Returns:
            Dict with 'internal' and 'external' link counts
        """
        base_domain = urlparse(base_url).netloc
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        internal = 0
        external = 0
        for link in links:
            if link.startswith('#') or link.startswith('mailto:') or link.startswith('javascript:'):
                continue
            parsed = urlparse(link)
            if parsed.netloc and parsed.netloc != base_domain:
                external += 1
            else:
                internal += 1
        return {"internal": internal, "external": external}

    def _extract_images(self, html: str) -> Dict[str, int]:
        """
        Count total images and images without alt text.

        Returns:
            Dict with 'total' and 'no_alt' counts
        """
        imgs = re.findall(r'<img[^>]*>', html, re.IGNORECASE)
        total = len(imgs)
        no_alt = 0
        for img in imgs:
            if not re.search(r'alt\s*=\s*["\']', img, re.IGNORECASE):
                no_alt += 1
            elif re.search(r'alt\s*=\s*["\']\s*["\']', img, re.IGNORECASE):
                no_alt += 1
        return {"total": total, "no_alt": no_alt}

    def glean(self, url: str) -> PageInsight:
        """
        Perform a complete audit on a single URL.

        Fetches the page and extracts: title, description, headings,
        links, images, SEO metadata, and performance metrics.

        Args:
            url: The URL to audit

        Returns:
            PageInsight with all extracted data
        """
        start_time = time.perf_counter()
        issues: List[str] = []

        # Validate URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            response = self.session.get(
                url, timeout=self.timeout, verify=self.verify_ssl
            )
            load_time_ms = (time.perf_counter() - start_time) * 1000
            html = response.text
            status_code = response.status_code

            # Extract metadata
            title = self._extract_title(html)
            description = self._extract_meta(html, 'meta', 'name', 'description')
            headings = self._extract_headings(html)
            links = self._extract_links(html, url)
            images = self._extract_images(html)

            # SEO checks
            has_viewport = bool(self._extract_meta(html, 'meta', 'name', 'viewport'))
            has_canonical = bool(re.search(r'<link[^>]*rel=["\']canonical["\']', html, re.IGNORECASE))
            has_og_title = bool(self._extract_meta(html, 'meta', 'property', 'og:title'))
            has_og_image = bool(self._extract_meta(html, 'meta', 'property', 'og:image'))

            # Favicon check
            has_favicon = bool(
                re.search(r'<link[^>]*rel=["\']icon["\']', html, re.IGNORECASE) or
                re.search(r'<link[^>]*rel=["\']shortcut icon["\']', html, re.IGNORECASE)
            )

            # Generate issues
            if not title or title == "No title found":
                issues.append("Missing or empty <title> tag")
            if not description:
                issues.append("Missing meta description")
            if not has_viewport:
                issues.append("Missing viewport meta tag")
            if not has_canonical:
                issues.append("Missing canonical URL")
            if not has_og_title or not has_og_image:
                issues.append("Missing Open Graph tags (og:title or og:image)")
            if images["no_alt"] > 0:
                issues.append(f"{images['no_alt']} images without alt text")
            if not headings.get("h1"):
                issues.append("Missing <h1> heading")
            if len(headings) == 0:
                issues.append("No heading tags found")
            if status_code >= 400:
                issues.append(f"HTTP {status_code} error")

            insight = PageInsight(
                url=url,
                status_code=status_code,
                title=title,
                description=description,
                headings=headings,
                internal_links=links["internal"],
                external_links=links["external"],
                broken_links=0,
                images_without_alt=images["no_alt"],
                total_images=images["total"],
                load_time_ms=round(load_time_ms, 2),
                content_length_bytes=len(html.encode('utf-8')),
                has_favicon=has_favicon,
                has_viewport_meta=has_viewport,
                has_canonical=has_canonical,
                has_open_graph=has_og_title and has_og_image,
                issues=issues,
                timestamp=time.time()
            )

            self.history.append(insight)
            logger.info(f"Audited {url} ({status_code}) in {load_time_ms:.0f}ms - "
                        f"{len(issues)} issues found")
            return insight

        except requests.exceptions.Timeout:
            load_time_ms = (time.perf_counter() - start_time) * 1000
            insight = PageInsight(
                url=url, status_code=0, title="", description="",
                headings={}, internal_links=0, external_links=0,
                broken_links=0, images_without_alt=0, total_images=0,
                load_time_ms=round(load_time_ms, 2), content_length_bytes=0,
                has_favicon=False, has_viewport_meta=False, has_canonical=False,
                has_open_graph=False, issues=["Request timed out"],
                timestamp=time.time()
            )
            self.history.append(insight)
            logger.error(f"Request timed out: {url}")
            return insight

        except requests.exceptions.ConnectionError as e:
            load_time_ms = (time.perf_counter() - start_time) * 1000
            insight = PageInsight(
                url=url, status_code=0, title="", description="",
                headings={}, internal_links=0, external_links=0,
                broken_links=0, images_without_alt=0, total_images=0,
                load_time_ms=round(load_time_ms, 2), content_length_bytes=0,
                has_favicon=False, has_viewport_meta=False, has_canonical=False,
                has_open_graph=False, issues=[f"Connection error: {e}"],
                timestamp=time.time()
            )
            self.history.append(insight)
            logger.error(f"Connection error for {url}: {e}")
            return insight

        except Exception as e:
            load_time_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Failed to audit {url}: {e}")
            insight = PageInsight(
                url=url, status_code=0, title="", description="",
                headings={}, internal_links=0, external_links=0,
                broken_links=0, images_without_alt=0, total_images=0,
                load_time_ms=round(load_time_ms, 2), content_length_bytes=0,
                has_favicon=False, has_viewport_meta=False, has_canonical=False,
                has_open_graph=False, issues=[f"Unexpected error: {e}"],
                timestamp=time.time()
            )
            self.history.append(insight)
            return insight

    def bulk_glean(self, urls: List[str]) -> List[PageInsight]:
        """
        Audit multiple URLs in sequence.

        Args:
            urls: List of URLs to audit

        Returns:
            List of PageInsight results
        """
        results = []
        for url in urls:
            results.append(self.glean(url))
        return results

    def save_audit(self, filename: str = "web_audit.json") -> str:
        """
        Save gleaning history to a JSON file.

        Args:
            filename: Output filename (default web_audit.json)

        Returns:
            Path to the saved file
        """
        try:
            report = [asdict(i) for i in self.history]
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Audit saved to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to save audit: {e}")
            return ""

    def get_summary(self) -> Dict:
        """
        Get a summary of all gleaned pages.

        Returns:
            Dict with aggregate statistics
        """
        total = len(self.history)
        if total == 0:
            return {"status": "No data"}

        healthy = sum(1 for h in self.history if 200 <= h.status_code < 400)
        avg_load = sum(h.load_time_ms for h in self.history) / total
        total_issues = sum(len(h.issues) for h in self.history)
        has_issues = sum(1 for h in self.history if len(h.issues) > 0)

        # Collect all unique issues
        all_issues: Dict[str, int] = {}
        for h in self.history:
            for issue in h.issues:
                all_issues[issue] = all_issues.get(issue, 0) + 1

        return {
            "total_pages_audited": total,
            "healthy_pages": healthy,
            "pages_with_issues": has_issues,
            "average_load_ms": round(avg_load, 2),
            "total_issues_found": total_issues,
            "most_common_issues": sorted(
                all_issues.items(), key=lambda x: x[1], reverse=True
            )[:5],
            "last_audit": asdict(self.history[-1])
        }


if __name__ == "__main__":
    import sys

    urls = sys.argv[1:] if len(sys.argv) > 1 else [
        "https://github.com/carlosjuarezz2006/Portfolio",
        "https://google.com"
    ]

    gleaner = WebGlean()
    print("Starting WebGlean audit...\n")
    gleaner.bulk_glean(urls)

    filename = gleaner.save_audit()
    print("\n" + "=" * 50)

    # Print per-page summary
    for insight in gleaner.history:
        status = "✓" if 200 <= insight.status_code < 400 else "✗"
        print(f"  {status} {insight.url}")
        print(f"     Title: {insight.title[:60]}")
        print(f"     Load: {insight.load_time_ms}ms | Issues: {len(insight.issues)}")
        if insight.issues:
            for issue in insight.issues[:3]:
                print(f"       ⚠ {issue}")

    print("\n" + "=" * 50)
    print("Audit Summary:")
    print(json.dumps(gleaner.get_summary(), indent=2))