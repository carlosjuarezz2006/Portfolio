import unittest
from unittest.mock import patch, Mock
from monitors import DiskMonitor, NetworkMonitor, LoadMonitor, MemoryMonitor
from system_monitor_pro import SystemMonitor


class TestDiskMonitor(unittest.TestCase):
    """Test suite for DiskMonitor."""

    def test_disk_monitor_returns_expected_keys(self):
        """Disk monitor should return a dict with status and percent_used."""
        monitor = DiskMonitor()
        result = monitor.check()
        self.assertIn("status", result)
        self.assertIn("percent_used", result)

    def test_disk_monitor_values_are_positive(self):
        """Disk monitor values should be reasonable (positive)."""
        monitor = DiskMonitor()
        result = monitor.check()
        self.assertGreaterEqual(result["total_gb"], 0)
        self.assertGreaterEqual(result["percent_used"], 0)

    def test_disk_monitor_threshold(self):
        """DiskMonitor should accept a custom threshold."""
        monitor = DiskMonitor(threshold=50.0)
        result = monitor.check()
        self.assertIn("status", result)


class TestNetworkMonitor(unittest.TestCase):
    """Test suite for NetworkMonitor."""

    def test_network_monitor_returns_dict(self):
        """Network monitor should always return a dict."""
        monitor = NetworkMonitor()
        result = monitor.check()
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)

    def test_network_monitor_custom_host(self):
        """Network monitor should accept a custom target."""
        monitor = NetworkMonitor(host="1.1.1.1", port=80)
        result = monitor.check()
        self.assertIn("status", result)


class TestLoadMonitor(unittest.TestCase):
    """Test suite for LoadMonitor."""

    def test_load_monitor_returns_dict(self):
        """Load monitor should return a dict."""
        monitor = LoadMonitor()
        result = monitor.check()
        self.assertIsInstance(result, dict)
        # If supported, should have the 3 load averages
        if "1min" in result:
            self.assertIn("5min", result)
            self.assertIn("15min", result)


class TestMemoryMonitor(unittest.TestCase):
    """Test suite for MemoryMonitor (Linux only)."""

    def test_memory_monitor_returns_dict(self):
        """Memory monitor should always return a dict."""
        monitor = MemoryMonitor()
        result = monitor.check()
        self.assertIsInstance(result, dict)


class TestSystemMonitor(unittest.TestCase):
    """Test suite for SystemMonitor professional extension."""

    def test_system_monitor_init(self):
        """SystemMonitor should initialize with system info."""
        monitor = SystemMonitor()
        self.assertIn("os", monitor.system_info)
        self.assertIn("machine", monitor.system_info)

    def test_take_snapshot(self):
        """Snapshot should include disk_usage and system_info."""
        monitor = SystemMonitor()
        snapshot = monitor.take_snapshot()
        self.assertIn("disk_usage", snapshot)
        self.assertIn("system_info", snapshot)
        self.assertIn("timestamp", snapshot)

    def test_get_summary(self):
        """Summary should return a dict with snapshot count."""
        monitor = SystemMonitor()
        monitor.take_snapshot()
        summary = monitor.get_summary()
        self.assertIn("total_snapshots", summary)
        self.assertIn("last_snapshot", summary)

    def test_multiple_snapshots(self):
        """Multiple snapshots should be tracked."""
        monitor = SystemMonitor()
        monitor.take_snapshot()
        monitor.take_snapshot()
        monitor.take_snapshot()
        self.assertEqual(len(monitor.history), 3)


if __name__ == '__main__':
    unittest.main()