"""
Unit tests for WebGlean - Web Content Extraction and Validation Tool.
"""

import unittest
from unittest.mock import patch, MagicMock, Mock
import json
import tempfile
import os
import time
from web_glean import WebGlean, PageInsight


class TestWebGleanCore(unittest.TestCase):
    """Test suite for WebGlean web content extraction and validation."""

    def setUp(self):
        self.gleaner = WebGlean(timeout=5, verify_ssl=False)

    # --- Title Extraction ---
    def test_extract_title(self):
        """Title extraction from HTML."""
        html = "<html><head><title>My Test Page</title></head><body></body></html>"
        self.assertEqual(self.gleaner._extract_title(html), "My Test Page")

    def test_extract_title_empty(self):
        """Missing title should return fallback message."""
        html = "<html><head></head><body></body></html>"
        self.assertEqual(self.gleaner._extract_title(html), "No title found")

    def test_extract_title_special_chars(self):
        """Title with special characters should be preserved."""
        html = "<title>Café &amp; Büro — Test</title>"
        self.assertEqual(self.gleaner._extract_title(html), "Café &amp; Büro — Test")

    def test_extract_title_multiline(self):
        """Title spanning multiple lines should be extracted."""
        html = "<title>\n  My Multi-Line\n  Title\n</title>"
        self.assertEqual(self.gleaner._extract_title(html), "My Multi-Line Title")

    # --- Meta Extraction ---
    def test_extract_meta_description(self):
        """Meta description extraction."""
        html = '<meta name="description" content="A test description here">'
        result = self.gleaner._extract_meta(html, 'meta', 'name', 'description')
        self.assertEqual(result, "A test description here")

    def test_extract_meta_viewport(self):
        """Viewport meta tag extraction."""
        html = '<meta name="viewport" content="width=device-width, initial-scale=1">'
        result = self.gleaner._extract_meta(html, 'meta', 'name', 'viewport')
        self.assertEqual(result, "width=device-width, initial-scale=1")

    def test_extract_meta_missing(self):
        """Missing meta tag should return empty string."""
        html = "<html><head></head></html>"
        result = self.gleaner._extract_meta(html, 'meta', 'name', 'description')
        self.assertEqual(result, "")

    def test_extract_meta_case_insensitive(self):
        """Meta name matching should be case-insensitive."""
        html = '<META NAME="Description" CONTENT="Test">'
        result = self.gleaner._extract_meta(html, 'meta', 'name', 'description')
        self.assertEqual(result, "Test")

    # --- Heading Extraction ---
    def test_extract_headings(self):
        """Heading structure extraction."""
        html = "<h1>Main</h1><h2>Sub</h2><h2>Another</h2><h3>Detail</h3>"
        headings = self.gleaner._extract_headings(html)
        self.assertEqual(headings["h1"], 1)
        self.assertEqual(headings["h2"], 2)
        self.assertEqual(headings["h3"], 1)

    def test_extract_headings_empty(self):
        """No headings should return empty counts."""
        html = "<body><p>No headings here</p></body>"
        headings = self.gleaner._extract_headings(html)
        self.assertEqual(sum(headings.values()), 0)

    def test_extract_headings_nested(self):
        """Nested headings should still be counted."""
        html = "<div><h1>Outer</h1><div><h2>Inner</h2></div></div>"
        headings = self.gleaner._extract_headings(html)
        self.assertEqual(headings["h1"], 1)
        self.assertEqual(headings["h2"], 1)

    # --- Link Analysis ---
    def test_extract_links(self):
        """Link extraction should count internal and external links."""
        html = '<a href="https://example.com/page">Internal</a>' \
               '<a href="https://other.com">External</a>' \
               '<a href="/relative">Relative</a>'
        internal, external = self.gleaner._extract_links("https://example.com", html)
        self.assertEqual(internal, 2)  # /relative same domain, https://example.com same domain
        self.assertEqual(external, 1)

    def test_extract_links_no_links(self):
        """No links should return zero counts."""
        html = "<p>No links here</p>"
        internal, external = self.gleaner._extract_links("https://example.com", html)
        self.assertEqual(internal, 0)
        self.assertEqual(external, 0)

    def test_extract_links_subdomain(self):
        """Subdomain links should still be counted."""
        html = '<a href="https://sub.example.com/page">Subdomain</a>'
        internal, external = self.gleaner._extract_links("https://example.com", html)
        # If subdomain is considered same domain
        self.assertEqual(internal + external, 1)

    # --- Image Analysis ---
    def test_extract_images(self):
        """Image extraction should count total and alt-less images."""
        html = '<img src="a.jpg" alt="A"><img src="b.jpg"><img src="c.jpg" alt="C">'
        total, no_alt = self.gleaner._extract_images(html)
        self.assertEqual(total, 3)
        self.assertEqual(no_alt, 1)

    def test_extract_images_no_images(self):
        """No images should return zero counts."""
        html = "<p>No images</p>"
        total, no_alt = self.gleaner._extract_images(html)
        self.assertEqual(total, 0)
        self.assertEqual(no_alt, 0)

    def test_extract_images_empty_alt(self):
        """Empty alt attribute should count as no alt."""
        html = '<img src="a.jpg" alt="">'
        total, no_alt = self.gleaner._extract_images(html)
        self.assertEqual(total, 1)
        self.assertEqual(no_alt, 1)

    # --- Favicon Detection ---
    def test_has_favicon(self):
        """Favicon detection."""
        html = '<link rel="icon" href="favicon.ico">'
        self.assertTrue(self.gleaner._has_favicon(html))

    def test_has_favicon_missing(self):
        """Missing favicon returns False."""
        html = "<html><head></head></html>"
        self.assertFalse(self.gleaner._has_favicon(html))

    def test_has_favicon_shortcut(self):
        """Shortcut icon should also be detected."""
        html = '<link rel="shortcut icon" href="favicon.ico">'
        self.assertTrue(self.gleaner._has_favicon(html))

    # --- Open Graph Detection ---
    def test_has_open_graph(self):
        """Open Graph meta tag detection."""
        html = '<meta property="og:title" content="Test">'
        self.assertTrue(self.gleaner._has_open_graph(html))

    def test_has_open_graph_missing(self):
        """Missing OG tags returns False."""
        html = "<html><head></head></html>"
        self.assertFalse(self.gleaner._has_open_graph(html))

    # --- Canonical Detection ---
    def test_has_canonical(self):
        """Canonical link detection."""
        html = '<link rel="canonical" href="https://example.com/">'
        self.assertTrue(self.gleaner._has_canonical(html))

    def test_has_canonical_missing(self):
        """Missing canonical returns False."""
        html = "<html><head></head></html>"
        self.assertFalse(self.gleaner._has_canonical(html))

    # --- Issue Detection ---
    def test_detect_issues_missing_title(self):
        """Missing title should generate an issue."""
        insight = PageInsight(
            url="https://example.com", status_code=200, title="No title found",
            description="", headings={}, internal_links=0, external_links=0,
            broken_links=0, images_without_alt=0, total_images=0,
            load_time_ms=50.0, content_length_bytes=100,
            has_favicon=False, has_viewport_meta=False, has_canonical=False,
            has_open_graph=False, issues=[], timestamp=time.time()
        )
        issues = self.gleaner._detect_issues(insight)
        self.assertIn("Missing or empty <title> tag", issues)

    def test_detect_issues_missing_description(self):
        """Missing description should generate an issue."""
        insight = PageInsight(
            url="https://example.com", status_code=200, title="My Title",
            description="", headings={}, internal_links=0, external_links=0,
            broken_links=0, images_without_alt=0, total_images=0,
            load_time_ms=50.0, content_length_bytes=100,
            has_favicon=False, has_viewport_meta=False, has_canonical=False,
            has_open_graph=False, issues=[], timestamp=time.time()
        )
        issues = self.gleaner._detect_issues(insight)
        self.assertIn("Missing meta description", issues)

    def test_detect_issues_images_without_alt(self):
        """Images without alt should generate an issue."""
        insight = PageInsight(
            url="https://example.com", status_code=200, title="My Title",
            description="A description", headings={}, internal_links=0, external_links=0,
            broken_links=0, images_without_alt=3, total_images=5,
            load_time_ms=50.0, content_length_bytes=100,
            has_favicon=False, has_viewport_meta=False, has_canonical=False,
            has_open_graph=False, issues=[], timestamp=time.time()
        )
        issues = self.gleaner._detect_issues(insight)
        self.assertTrue(any("alt" in i.lower() for i in issues))

    def test_detect_issues_no_issues(self):
        """A well-formed page should have no issues."""
        insight = PageInsight(
            url="https://example.com", status_code=200, title="My Title",
            description="A description", headings={"h1": 1}, internal_links=5, external_links=2,
            broken_links=0, images_without_alt=0, total_images=3,
            load_time_ms=50.0, content_length_bytes=100,
            has_favicon=True, has_viewport_meta=True, has_canonical=True,
            has_open_graph=True, issues=[], timestamp=time.time()
        )
        issues = self.gleaner._detect_issues(insight)
        self.assertEqual(len(issues), 0)

    def test_detect_issues_broken_links(self):
        """Broken links should generate an issue."""
        insight = PageInsight(
            url="https://example.com", status_code=200, title="Title",
            description="Desc", headings={}, internal_links=5, external_links=2,
            broken_links=2, images_without_alt=0, total_images=0,
            load_time_ms=50.0, content_length_bytes=100,
            has_favicon=False, has_viewport_meta=False, has_canonical=False,
            has_open_graph=False, issues=[], timestamp=time.time()
        )
        issues = self.gleaner._detect_issues(insight)
        self.assertTrue(any("broken" in i.lower() for i in issues))

    # --- Bulk Glean ---
    @patch('web_glean.WebGlean.glean')
    def test_bulk_glean(self, mock_glean):
        """Bulk glean should call glean for each URL."""
        mock_glean.return_value = PageInsight(
            url="https://example.com", status_code=200, title="Test",
            description="", headings={}, internal_links=0, external_links=0,
            broken_links=0, images_without_alt=0, total_images=0,
            load_time_ms=50.0, content_length_bytes=100,
            has_favicon=False, has_viewport_meta=False, has_canonical=False,
            has_open_graph=False, issues=[], timestamp=time.time()
        )
        results = self.gleaner.bulk_glean(["https://example.com", "https://test.com"])
        self.assertEqual(len(results), 2)

    # --- HTTP Error Handling ---
    def test_glean_http_error(self):
        """HTTP error should return error insight."""
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception("Connection error")
            result = self.gleaner.glean("https://example.com")
            self.assertEqual(result.status_code, 0)
            self.assertIn("error", result.title.lower())

    # --- Empty URL ---
    def test_glean_empty_url(self):
        """Empty URL should return error insight."""
        result = self.gleaner.glean("")
        self.assertEqual(result.status_code, 0)

    # --- Summary ---
    def test_get_summary(self):
        """Summary should return expected structure."""
        summary = self.gleaner.get_summary()
        self.assertIn("total_pages_audited", summary)
        self.assertIn("average_load_time_ms", summary)
        self.assertIn("total_issues_found", summary)


if __name__ == '__main__':
    unittest.main()