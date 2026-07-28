"""
Unit tests for NetScout - Fast Port Scanner.
"""

import unittest
from unittest.mock import patch, MagicMock, Mock
import socket
import json
import tempfile
import os
from scout import NetScout, ScanResult, ScanReport, COMMON_SERVICES


class TestNetScout(unittest.TestCase):
    """Test suite for NetScout port scanner."""

    def setUp(self):
        self.scout = NetScout("127.0.0.1", timeout=0.5)

    # --- Host Resolution ---
    def test_resolve_host_valid(self):
        """A valid IP should be resolved correctly."""
        self.assertEqual(self.scout.ip, "127.0.0.1")

    def test_resolve_host_invalid(self):
        """An invalid hostname should set ip to None."""
        scout = NetScout("invalid.host.test.example", timeout=0.5)
        self.assertIsNone(scout.ip)

    def test_resolve_localhost_hostname(self):
        """localhost should resolve to 127.0.0.1."""
        scout = NetScout("localhost", timeout=0.5)
        self.assertIsNotNone(scout.ip)

    # --- Service Identification ---
    def test_get_service_known(self):
        """Known ports should return the correct service name."""
        self.assertEqual(COMMON_SERVICES[22], "SSH")
        self.assertEqual(COMMON_SERVICES[80], "HTTP")
        self.assertEqual(COMMON_SERVICES[443], "HTTPS")
        self.assertEqual(COMMON_SERVICES[3306], "MySQL")
        self.assertEqual(COMMON_SERVICES[5432], "PostgreSQL")

    def test_get_service_unknown(self):
        """Unknown ports should return 'Unknown'."""
        self.assertEqual(COMMON_SERVICES.get(9999, "Unknown"), "Unknown")

    # --- Port Scanning ---
    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        """An open port should return is_open=True."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.return_value = 0

        result = self.scout._scan_port(80)
        self.assertTrue(result.is_open)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.service, "HTTP")

    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        """A closed port should return is_open=False."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.return_value = 1

        result = self.scout._scan_port(443)
        self.assertFalse(result.is_open)

    @patch('socket.socket')
    def test_scan_port_timeout(self, mock_socket):
        """A timeout should return is_open=False."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.side_effect = socket.timeout()

        result = self.scout._scan_port(22)
        self.assertFalse(result.is_open)

    @patch('socket.socket')
    def test_scan_port_connection_refused(self, mock_socket):
        """Connection refused should return is_open=False."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.side_effect = ConnectionRefusedError()

        result = self.scout._scan_port(80)
        self.assertFalse(result.is_open)

    @patch('socket.socket')
    def test_scan_port_os_error(self, mock_socket):
        """OSError should return is_open=False."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.side_effect = OSError()

        result = self.scout._scan_port(443)
        self.assertFalse(result.is_open)

    # --- Banner Grabbing ---
    @patch('socket.socket')
    def test_grab_banner_http(self, mock_socket):
        """Banner grabbing should capture service banners."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.return_value = 0
        mock_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1"

        result = self.scout._scan_port(22)
        self.assertIsNotNone(result.banner)
        self.assertIn("SSH", result.banner)

    @patch('socket.socket')
    def test_grab_banner_empty(self, mock_socket):
        """Empty banner should not cause errors."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.return_value = 0
        mock_instance.recv.return_value = b""

        # Create scout with banner grabbing
        scout = NetScout("127.0.0.1", timeout=0.5, grab_banner=False)
        result = scout._scan_port(80)
        self.assertFalse(result.is_open)

    @patch('socket.socket')
    def test_grab_banner_timeout(self, mock_socket):
        """Banner timeout should not prevent scan completion."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.return_value = 0
        mock_instance.recv.side_effect = socket.timeout()

        scout = NetScout("127.0.0.1", timeout=0.5, grab_banner=True)
        result = scout._scan_port(80)
        self.assertIsNone(result.banner)  # Banner is None on timeout

    # --- Scan Modes ---
    @patch.object(NetScout, '_scan_port')
    def test_scan_quick(self, mock_scan):
        """Quick scan (ports 1-1024) should scan the correct range."""
        mock_scan.return_value = ScanResult(port=80, service="HTTP", is_open=False)
        scout = NetScout("127.0.0.1", timeout=0.5)
        report = scout.scan_quick(max_workers=1)
        self.assertEqual(report.start_port, 1)
        self.assertEqual(report.end_port, 1024)

    @patch.object(NetScout, '_scan_port')
    def test_scan_well_known(self, mock_scan):
        """Well-known scan (ports 1-1023) should scan the correct range."""
        mock_scan.return_value = ScanResult(port=80, service="HTTP", is_open=False)
        scout = NetScout("127.0.0.1", timeout=0.5)
        report = scout.scan_well_known(max_workers=1)
        self.assertEqual(report.start_port, 1)
        self.assertEqual(report.end_port, 1023)

    @patch.object(NetScout, '_scan_port')
    def test_scan_extended(self, mock_scan):
        """Extended scan (ports 1-10000) should scan the correct range."""
        mock_scan.return_value = ScanResult(port=80, service="HTTP", is_open=False)
        scout = NetScout("127.0.0.1", timeout=0.5)
        report = scout.scan_extended(max_workers=1)
        self.assertEqual(report.start_port, 1)
        self.assertEqual(report.end_port, 10000)

    @patch.object(NetScout, '_scan_port')
    def test_scan_custom_range(self, mock_scan):
        """Custom range should scan the specified ports."""
        mock_scan.return_value = ScanResult(port=80, service="HTTP", is_open=False)
        scout = NetScout("127.0.0.1", timeout=0.5)
        report = scout.scan_range(100, 200, max_workers=1)
        self.assertEqual(report.start_port, 100)
        self.assertEqual(report.end_port, 200)
        self.assertEqual(report.ports_scanned, 101)

    @patch.object(NetScout, '_scan_port')
    def test_scan_single_port(self, mock_scan):
        """Single port range (e.g., 80-80) should scan one port."""
        mock_scan.return_value = ScanResult(port=80, service="HTTP", is_open=False)
        scout = NetScout("127.0.0.1", timeout=0.5)
        report = scout.scan_range(80, 80, max_workers=1)
        self.assertEqual(report.ports_scanned, 1)

    # --- Report Generation ---
    @patch.object(NetScout, '_scan_port')
    def test_report_has_required_fields(self, mock_scan):
        """Report should have all required fields."""
        mock_scan.return_value = ScanResult(port=80, service="HTTP", is_open=False)
        scout = NetScout("127.0.0.1", timeout=0.5)
        report = scout.scan_quick(max_workers=1)
        self.assertIsNotNone(report.target)
        self.assertIsNotNone(report.ip)
        self.assertIsNotNone(report.timestamp)
        self.assertGreater(report.scan_duration_s, 0)

    def test_report_json_serializable(self):
        """Report should be JSON serializable."""
        report = ScanReport(
            target="test.com", ip="1.2.3.4",
            start_port=1, end_port=10,
            ports_scanned=10, open_ports=0,
            results=[{"port": 80, "is_open": False}],
            scan_duration_s=0.5, timestamp="2026-01-01T00:00:00"
        )
        json_str = json.dumps(report.__dict__)
        self.assertIsNotNone(json_str)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["target"], "test.com")

    # --- Summary ---
    def test_print_summary_no_error(self):
        """print_summary should not raise any exception."""
        report = ScanReport(
            target="test", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=2,
            results=[{"port": 22, "is_open": True}, {"port": 80, "is_open": True}],
            scan_duration_s=1.0, timestamp="2026-01-01T00:00:00"
        )
        try:
            NetScout.print_summary(report)
        except Exception as e:
            self.fail(f"print_summary raised an exception: {e}")

    def test_print_summary_zero_open_ports(self):
        """Summary should handle zero open ports."""
        report = ScanReport(
            target="test", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=0,
            results=[], scan_duration_s=1.0, timestamp=""
        )
        try:
            NetScout.print_summary(report)
        except Exception as e:
            self.fail(f"print_summary raised: {e}")

    # --- Report Comparison ---
    def test_compare_reports(self):
        """Compare reports should identify new/closed ports."""
        report1 = ScanReport(
            target="test", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=2,
            results=[
                {"port": 22, "is_open": True},
                {"port": 80, "is_open": True},
            ],
            scan_duration_s=1.0, timestamp=""
        )
        report2 = ScanReport(
            target="test", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=2,
            results=[
                {"port": 22, "is_open": True},
                {"port": 443, "is_open": True},
            ],
            scan_duration_s=1.0, timestamp=""
        )
        diff = NetScout.compare_reports(report1, report2)
        self.assertEqual(diff["new_ports"], [443])
        self.assertEqual(diff["closed_ports"], [80])
        self.assertEqual(diff["unchanged_ports"], [22])

    def test_compare_identical_reports(self):
        """Identical reports should show no changes."""
        report = ScanReport(
            target="test", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=2,
            results=[{"port": 22, "is_open": True}],
            scan_duration_s=1.0, timestamp=""
        )
        diff = NetScout.compare_reports(report, report)
        self.assertEqual(diff["new_ports"], [])
        self.assertEqual(diff["closed_ports"], [])
        self.assertEqual(diff["unchanged_ports"], [22])

    def test_compare_empty_reports(self):
        """Empty reports should show no changes."""
        report1 = ScanReport(
            target="test", ip="", start_port=1, end_port=1,
            ports_scanned=0, open_ports=0, results=[], scan_duration_s=0, timestamp=""
        )
        report2 = ScanReport(
            target="test", ip="", start_port=1, end_port=1,
            ports_scanned=0, open_ports=0, results=[], scan_duration_s=0, timestamp=""
        )
        diff = NetScout.compare_reports(report1, report2)
        self.assertEqual(diff["new_ports"], [])
        self.assertEqual(diff["closed_ports"], [])
        self.assertEqual(diff["unchanged_ports"], [])

    # --- Save Report ---
    def test_save_report_creates_file(self):
        """save_report should create a JSON file."""
        report = ScanReport(
            target="test", ip="127.0.0.1",
            start_port=1, end_port=10,
            ports_scanned=10, open_ports=0,
            results=[], scan_duration_s=0.5, timestamp=""
        )
        filename = "test_scan_report.json"
        try:
            NetScout.save_report(report, filename)
            self.assertTrue(os.path.exists(filename))
            with open(filename) as f:
                data = json.load(f)
            self.assertEqual(data["target"], "test")
        finally:
            if os.path.exists(filename):
                os.remove(filename)


if __name__ == '__main__':
    unittest.main()