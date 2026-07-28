"""
Unit tests for CertSentinel - SSL/TLS Certificate Monitoring Tool.
"""

import unittest
from unittest.mock import patch, MagicMock, Mock
from sentinel import CertSentinel, CertInfo, CertReport
import datetime
import json
import os
import socket
import ssl


class TestCertSentinelCore(unittest.TestCase):
    """Test suite for CertSentinel core functionality."""

    def setUp(self):
        self.sentinel = CertSentinel(timeout=5)

    def tearDown(self):
        if os.path.exists("cert_report.json"):
            os.remove("cert_report.json")

    def _make_mock_cert(self, days_from_now=30):
        """Helper to create a mock certificate with configurable expiry."""
        future = (
            datetime.datetime.utcnow() + datetime.timedelta(days=days_from_now)
        )
        return {
            "notAfter": future.strftime("%b %d %H:%M:%S %Y GMT"),
            "issuer": ((("organizationName", "Test CA"),),),
            "subject": ((("commonName", "example.com"),),),
            "serialNumber": "1234567890ABCDEF"
        }

    @patch("socket.create_connection")
    @patch("ssl.SSLContext.wrap_socket")
    def test_get_cert_info_success(self, mock_wrap, mock_connect):
        """Successful certificate retrieval returns structured CertInfo."""
        mock_ssock = MagicMock()
        mock_wrap.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = self._make_mock_cert(30)

        info = self.sentinel.get_cert_info("example.com")
        self.assertIsNotNone(info)
        self.assertIsInstance(info, CertInfo)
        self.assertEqual(info.domain, "example.com")
        self.assertEqual(info.issuer, "Test CA")
        self.assertEqual(info.subject, "example.com")
        self.assertEqual(info.serial_number, "1234567890ABCDEF")
        self.assertGreater(info.days_left, 0)
        self.assertTrue(info.is_valid)
        self.assertIsNone(info.error)

    @patch("socket.create_connection")
    @patch("ssl.SSLContext.wrap_socket")
    def test_get_cert_info_expired(self, mock_wrap, mock_connect):
        """Expired certificate returns negative days_left."""
        mock_ssock = MagicMock()
        mock_wrap.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = self._make_mock_cert(-30)

        info = self.sentinel.get_cert_info("example.com")
        self.assertIsNotNone(info)
        self.assertLess(info.days_left, 0)
        self.assertFalse(info.is_valid)

    @patch("socket.create_connection")
    def test_get_cert_info_timeout(self, mock_connect):
        """Connection timeout returns error CertInfo."""
        mock_connect.side_effect = socket.timeout()

        info = self.sentinel.get_cert_info("timeout.example.com")
        self.assertIsNotNone(info)
        self.assertFalse(info.is_valid)
        self.assertEqual(info.error, "Connection timeout")

    @patch("socket.create_connection")
    def test_get_cert_info_dns_failure(self, mock_connect):
        """DNS resolution failure returns error CertInfo."""
        mock_connect.side_effect = socket.gaierror()

        info = self.sentinel.get_cert_info("invalid.example.com")
        self.assertIsNotNone(info)
        self.assertFalse(info.is_valid)
        self.assertEqual(info.error, "DNS resolution failed")

    @patch("socket.create_connection")
    @patch("ssl.SSLContext.wrap_socket")
    def test_get_cert_info_ssl_error(self, mock_wrap, mock_connect):
        """SSL error returns error CertInfo."""
        mock_ssock = MagicMock()
        mock_wrap.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.side_effect = ssl.SSLError("certificate verify failed")

        info = self.sentinel.get_cert_info("example.com")
        self.assertIsNotNone(info)
        self.assertFalse(info.is_valid)
        self.assertIn("SSL error", info.error)

    def test_health_status_healthy(self):
        """Healthy certificate returns green status."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="2027-01-01", days_left=90,
                issuer="CA", subject="test.com",
                serial_number="ABC", is_valid=True,
                timestamp=0.0
            )
            status = self.sentinel.check_health("test.com")
            self.assertIn("🟢", status)

    def test_health_status_warning(self):
        """Warning threshold returns yellow status."""
        self.sentinel.warn_days = 30
        self.sentinel.critical_days = 14
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="2026-08-01", days_left=20,
                issuer="CA", subject="test.com",
                serial_number="ABC", is_valid=True,
                timestamp=0.0
            )
            status = self.sentinel.check_health("test.com")
            self.assertIn("🟡", status)

    def test_health_status_critical(self):
        """Critical threshold returns orange status."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="2026-07-30", days_left=5,
                issuer="CA", subject="test.com",
                serial_number="ABC", is_valid=True,
                timestamp=0.0
            )
            status = self.sentinel.check_health("test.com")
            self.assertIn("🟠", status)

    def test_health_status_expired(self):
        """Expired certificate returns red status."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="2026-06-01", days_left=-10,
                issuer="CA", subject="test.com",
                serial_number="ABC", is_valid=False,
                timestamp=0.0
            )
            status = self.sentinel.check_health("test.com")
            self.assertIn("🔴 EXPIRED", status)

    def test_health_status_error(self):
        """Error during check returns error status."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="", days_left=0,
                issuer="", subject="", serial_number="",
                is_valid=False, error="Connection timeout",
                timestamp=0.0
            )
            status = self.sentinel.check_health("test.com")
            self.assertIn("🔴 ERROR", status)

    def test_get_status_labels(self):
        """get_status returns correct machine-readable labels."""
        self.assertEqual(
            self.sentinel.get_status(
                CertInfo("t", 443, "", 90, "C", "t", "S", True)
            ),
            "healthy"
        )
        self.assertEqual(
            self.sentinel.get_status(
                CertInfo("t", 443, "", 20, "C", "t", "S", True)
            ),
            "warning"
        )
        self.assertEqual(
            self.sentinel.get_status(
                CertInfo("t", 443, "", 5, "C", "t", "S", True)
            ),
            "critical"
        )
        self.assertEqual(
            self.sentinel.get_status(
                CertInfo("t", 443, "", -1, "C", "t", "S", False)
            ),
            "expired"
        )
        self.assertEqual(
            self.sentinel.get_status(
                CertInfo("t", 443, "", 0, "", "", "", False, error="timeout")
            ),
            "error"
        )

    def test_history_tracking(self):
        """Each cert check should be tracked in history."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="2027-01-01", days_left=90,
                issuer="CA", subject="test.com",
                serial_number="ABC", is_valid=True,
                timestamp=0.0
            )
            self.sentinel.check_health("test.com")
            self.assertEqual(len(self.sentinel.history), 1)

    def test_summary_with_data(self):
        """Summary should reflect check history."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="2027-01-01", days_left=90,
                issuer="CA", subject="test.com",
                serial_number="ABC", is_valid=True,
                timestamp=0.0
            )
            self.sentinel.check_health("test.com")
            summary = self.sentinel.get_summary()
            self.assertEqual(summary["total_checks"], 1)
            self.assertEqual(summary["healthy"], 1)

    def test_summary_empty(self):
        """Empty history should return no-data status."""
        summary = self.sentinel.get_summary()
        self.assertEqual(summary["status"], "No data")
        self.assertEqual(summary["total_checks"], 0)

    def test_save_report(self):
        """Save report should create a valid JSON file."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="2027-01-01", days_left=90,
                issuer="CA", subject="test.com",
                serial_number="ABC", is_valid=True,
                timestamp=0.0
            )
            self.sentinel.check_health("test.com")
            path = self.sentinel.save_report()
            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                data = json.load(f)
            self.assertIn("summary", data)
            self.assertIn("checks", data)
            self.assertEqual(data["summary"]["total_checks"], 1)

    def test_cert_report_dataclass(self):
        """CertReport stores all fields correctly."""
        report = CertReport(
            total_domains=2, healthy=2, warning=0,
            critical=0, expired=0, errors=0,
            details=[], timestamp=1234567890.0
        )
        self.assertEqual(report.total_domains, 2)
        self.assertEqual(report.healthy, 2)
        self.assertEqual(report.errors, 0)

    @patch("socket.create_connection")
    @patch("ssl.SSLContext.wrap_socket")
    def test_bulk_check_includes_all_domains(self, mock_wrap, mock_connect):
        """Bulk check should return results for all domains."""
        mock_ssock = MagicMock()
        mock_wrap.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = self._make_mock_cert(90)

        report = self.sentinel.bulk_check(
            ["example.com", "test.org", "demo.net"]
        )
        self.assertEqual(report.total_domains, 3)
        self.assertEqual(report.healthy, 3)
        self.assertEqual(report.errors, 0)

    def test_no_certificate_returned(self):
        """When no certificate is returned, it should be handled."""
        with patch.object(CertSentinel, "get_cert_info") as mock_get:
            mock_get.return_value = CertInfo(
                domain="test.com", port=443,
                expires="", days_left=0,
                issuer="", subject="", serial_number="",
                is_valid=False, error="No certificate returned",
                timestamp=0.0
            )
            info = self.sentinel.get_cert_info("test.com")
            self.assertFalse(info.is_valid)
            self.assertEqual(info.error, "No certificate returned")


if __name__ == "__main__":
    unittest.main()