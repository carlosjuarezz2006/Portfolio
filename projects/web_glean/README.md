# WebGlean

A professional web content extraction, SEO audit, and accessibility validation tool.

## Features
- **URL Content Extraction**: Fetches pages and extracts structured metadata (title, description, headings, links).
- **SEO Audit**: Checks for viewport meta, canonical URL, Open Graph tags, and favicon presence.
- **Accessibility Audit**: Counts images without alt text, identifies heading structure issues.
- **Link Analysis**: Categorizes links as internal/external; detects broken links.
- **Performance Metrics**: Measures load time and content size for each page.
- **Structured Reports**: Saves all audits to JSON with session history and aggregate statistics.
- **Bulk Mode**: Audit multiple URLs in a single call.

## Grok Build Standards
- **OOP Architecture**: Clean separation with `PageInsight` dataclass and `WebGlean` class with single-responsibility private methods.
- **Security**: Uses `requests` library with configurable timeouts, user-agent, and SSL verification.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 15+ unit tests.

## Usage
```python
from web_glean import WebGlean

gleaner = WebGlean()

# Audit a single page
insight = gleaner.glean("https://example.com")
print(f"Title: {insight.title}")
print(f"Load time: {insight.load_time_ms}ms")
print(f"Issues: {insight.issues}")

# Bulk audit
results = gleaner.bulk_glean([
    "https://github.com/carlosjuarezz2006/Portfolio",
    "https://google.com"
])

# Save report
gleaner.save_audit("audit_results.json")

# Get summary
print(gleaner.get_summary())
```

## CLI Usage
```bash
python web_glean.py https://example.com
python web_glean.py https://example.com https://github.com/carlosjuarezz2006/Portfolio
```