import unittest
import json
import os
from web_glean import WebGlean

class TestWebGlean(unittest.TestCase):
    def setUp(self):
        self.gleaner = WebGlean(timeout=5)

    def test_glean_google(self):
        """Test gleaning a known working URL."""
        insight = self.gleaner.glean("https://google.com")
        self.assertIn(insight.status_code, [200, 301, 302])
        self.assertIn("title", insight.__dict__)
        self.assertIsNotNone(insight.load_time_ms)

    def test_glean_invalid_url(self):
        """Test gleaning an invalid URL returns error insight."""
        insight = self.gleaner.glean("https://invalid.domain.test")
        self.assertEqual(insight.status_code, 0)
        self.assertTrue(len(insight.issues) > 0)

    def test_glean_empty_url(self):
        """Test gleaning with a malformed URL."""
        insight = self.gleaner.glean("not-a-url")
        self.assertEqual(insight.status_code, 0)
        self.assertTrue(len(insight.issues) > 0)

    def test_bulk_glean(self):
        """Test bulk gleaning multiple URLs."""
        urls = ["https://google.com", "https://invalid.domain.test"]
        results = self.gleaner.bulk_glean(urls)
        self.assertEqual(len(results), 2)

    def test_save_audit(self):
        """Test saving audit to JSON file."""
        self.gleaner.glean("https://google.com")
        self.gleaner.save_audit("test_audit.json")
        self.assertTrue(os.path.exists("test_audit.json"))
        with open("test_audit.json") as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        os.remove("test_audit.json")

    def test_get_summary_no_data(self):
        """Test summary with no data."""
        empty_gleaner = WebGlean()
        summary = empty_gleaner.get_summary()
        self.assertEqual(summary, {"status": "No data"})

    def test_get_summary_with_data(self):
        """Test summary with data."""
        self.gleaner.glean("https://google.com")
        summary = self.gleaner.get_summary()
        self.assertIn("total_pages", summary)
        self.assertIn("average_load_ms", summary)
        self.assertIn("total_issues_found", summary)

    def test_meta_extraction_empty(self):
        """Test extracting meta from empty HTML."""
        result = self.gleaner._extract_meta("", "description", "name")
        self.assertEqual(result, "")

    def test_count_headings_empty(self):
        """Test counting headings from empty HTML."""
        headings = self.gleaner._count_headings("")
        self.assertEqual(headings, {"h1": 0, "h2": 0, "h3": 0, "h4": 0, "h5": 0, "h6": 0})

    def test_find_links_empty(self):
        """Test finding links from empty HTML."""
        links = self.gleaner._find_links("", "https://example.com")
        self.assertEqual(links, {"internal": 0, "external": 0})

    def test_check_favicon(self):
        """Test favicon detection."""
        html_with = '<link rel="icon" href="favicon.ico">'
        html_without = '<html><head></head></html>'
        self.assertTrue(self.gleaner._check_has_favicon(html_with))
        self.assertFalse(self.gleaner._check_has_favicon(html_without))

    def test_check_viewport(self):
        """Test viewport meta detection."""
        html_with = '<meta name="viewport" content="width=device-width">'
        html_without = '<html><head></head></html>'
        self.assertTrue(self.gleaner._check_has_viewport(html_with))
        self.assertFalse(self.gleaner._check_has_viewport(html_without))

    def test_images_without_alt(self):
        """Test images without alt attribute detection."""
        html = '<img src="test.jpg"><img src="test2.jpg" alt="desc">'
        count = self.gleaner._count_images_without_alt(html)
        self.assertEqual(count, 1)


if __name__ == '__main__':
    unittest.main()