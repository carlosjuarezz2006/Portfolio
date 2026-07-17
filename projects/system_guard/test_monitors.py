import unittest
from monitors import DiskMonitor, NetworkMonitor, LoadMonitor

class TestSystemGuardMonitors(unittest.TestCase):
    def test_disk_monitor(self):
        monitor = DiskMonitor()
        result = monitor.check()
        self.assertIn("status", result)
        self.assertIn("percent_used", result)

    def test_network_monitor(self):
        # We assume 8.8.8.8 is reachable, but we check if result has 'status'
        monitor = NetworkMonitor()
        result = monitor.check()
        self.assertIn("status", result)

    def test_load_monitor(self):
        monitor = LoadMonitor()
        result = monitor.check()
        # Might return error if not supported, but should return a dict
        self.assertIsInstance(result, dict)

if __name__ == '__main__':
    unittest.main()
