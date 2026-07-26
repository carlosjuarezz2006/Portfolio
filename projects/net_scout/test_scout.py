import unittest
from unittest.mock import patch, MagicMock
import socket
import json
import tempfile
import os
from scout import NetScout, ScanResult, ScanReport, COMMON_SERVICES


class TestNetScout(unittest.TestCase):
    """Test suite for NetScout port scanner."""

    def setUp(self):
        self.scout = NetScout("127.0.0.1", timeout=0.5)

    def test_resolve_host_valid(self):
        """A valid IP should be resolved correctly."""
        self.assertEqual(self.scout.ip, "127.0.0.1")

    def test_resolve_host_invalid(self):
        """An invalid hostname should set ip to None."""
        scout = NetScout("invalid.host.test.example", timeout=0.5)
        self.assertIsNone(scout.ip)

    def test_get_service_known(self):
        """Known ports should return the correct service name."""
        self.assertEqual(COMMON_SERVICES[22], "SSH")
        self.assertEqual(COMMON_SERVICES[80], "HTTP")
        self.assertEqual(COMMON_SERVICES[443], "HTTPS")

    def test_get_service_unknown(self):
        """Unknown ports should return 'Unknown'."""
        self.assertEqual(COMMON_SERVICES.get(9999, "Unknown"), "Unknown")

    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        """An open port should return is_open=True."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.return_value = 0

        result = self.scout._scan_port(80)
        self.assertTrue(result.is_open)
        self.assertEqual(result.port, 80)

    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        """A closed port should return is_open=False."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.return_value = 1

        result = self.scout._scan_port(80)
        self.assertFalse(result.is_open)

    @patch('socket.socket')
    def test_scan_port_timeout(self, mock_socket):
        """A timeout should return is_open=False."""
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.connect_ex.side_effect = socket.timeout()

        result = self.scout._scan_port(80)
        self.assertFalse(result.is_open)

    def test_scan_range_no_target(self):
        """Scanning with no IP should return an empty report."""
        scout = NetScout("invalid.host.test.example", timeout=0.5)
        report = scout.scan_range(1, 100)
        self.assertEqual(report.ports_scanned, 0)
        self.assertEqual(report.open_ports, 0)

    def test_scan_quick_sets_correct_range(self):
        """Quick scan should scan ports 1-1024."""
        with patch.object(NetScout, 'scan_range', return_value=None) as mock_method:
            scout = NetScout("127.0.0.1")
            scout.scan_quick()
            mock_method.assert_called_with(1, 1024, 50)

    def test_scan_well_known_sets_correct_range(self):
        """Well-known scan should scan ports 1-1023."""
        with patch.object(NetScout, 'scan_range', return_value=None) as mock_method:
            scout = NetScout("127.0.0.1")
            scout.scan_well_known()
            mock_method.assert_called_with(1, 1023, 50)

    def test_scan_report_dataclass(self):
        """ScanReport should store all fields correctly."""
        report = ScanReport(
            target="test.local", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=2,
            results=[{"port": 22, "is_open": True}],
            scan_duration_s=5.5,
            timestamp="2026-01-01T00:00:00"
        )
        self.assertEqual(report.target, "test.local")
        self.assertEqual(report.open_ports, 2)
        self.assertEqual(report.scan_duration_s, 5.5)

    def test_scan_result_dataclass(self):
        """ScanResult should store all fields correctly."""
        result = ScanResult(port=443, service="HTTPS", is_open=True,
                            banner="Apache", latency_ms=12.5)
        self.assertEqual(result.port, 443)
        self.assertEqual(result.service, "HTTPS")
        self.assertTrue(result.is_open)
        self.assertEqual(result.banner, "Apache")
        self.assertEqual(result.latency_ms, 12.5)

    def test_save_report(self):
        """Save report should create a JSON file."""
        report = ScanReport(
            target="test.local", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=1,
            results=[{"port": 22, "service": "SSH", "is_open": True}],
            scan_duration_s=1.0,
            timestamp="2026-01-01T00:00:00"
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            filename = f.name

        try:
            saved = NetScout.save_report(report, filename)
            self.assertEqual(saved, filename)
            with open(filename, 'r') as f:
                data = json.load(f)
            self.assertEqual(data["target"], "test.local")
            self.assertEqual(data["open_ports"], 1)
        finally:
            os.unlink(filename)

    def test_print_summary_output(self):
        """Print summary should not raise errors."""
        report = ScanReport(
            target="test.local", ip="127.0.0.1",
            start_port=1, end_port=100,
            ports_scanned=100, open_ports=2,
            results=[
                {"port": 22, "service": "SSH", "is_open": True, "banner": None, "latency_ms": 5.0},
                {"port": 80, "service": "HTTP", "is_open": True, "banner": "Apache/2.4", "latency_ms": 10.0},
            ],
            scan_duration_s=2.5,
            timestamp="2026-01-01T00:00:00"
        )
        try:
            NetScout.print_summary(report)
        except Exception as e:
            self.fail(f"print_summary raised an exception: {e}")

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


if __name__ == '__main__':
    unittest.main()