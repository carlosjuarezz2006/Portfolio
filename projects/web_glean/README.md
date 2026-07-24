# WebGlean

WebGlean is a web content extraction and validation tool. It fetches URLs, extracts structured metadata, and audits pages for basic SEO and accessibility issues.

## Features
- **Structured Metadata Extraction**: Extracts page title, meta description, and heading structure (h1-h6).
- **SEO & Accessibility Audit**: Checks for missing titles, descriptions, favicons, viewport meta tags, and alt text on images.
- **Link Analysis**: Counts internal vs. external links on a page.
- **Bulk Scanning**: Glean multiple URLs and save results into a structured JSON report.
- **Performance Metrics**: Measures page load time for each request.

## Grok Build Standards
- **Cryptographic Security**: Uses `secrets` module for internal token generation in session handling.
- **OOP Architecture**: Clean separation of concerns with `PageInsight` dataclass and `WebGlean` class.
- **Professional Documentation**: Full type hinting, descriptive docstrings, and structured logging.

## Usage
```python
from web_glean import WebGlean

gleaner = WebGlean()
insight = gleaner.glean("https://example.com")
print(f"Title: {insight.title}")
print(f"Issues: {', '.join(insight.issues)}")
```