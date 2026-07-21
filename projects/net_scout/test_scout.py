import unittest
from unittest.mock import patch, MagicMock
from scout import NetScout
import socket

class TestNetScout(unittest.TestCase):
    def setUp(self):
        # Mock gethostbyname to avoid network dependency during init
        with patch('socket.gethostbyname', return_value='127.0.0.1'):
            self.scout = NetScout('localhost')

    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        # Mock connect_ex returning 0 (success/open)
        mock_instance = mock_socket.return_value.__enter__.return_value
        mock_instance.connect_ex.return_value = 0
        
        port, is_open = self.scout.scan_port(80)
        self.assertTrue(is_open)
        self.assertEqual(port, 80)

    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        # Mock connect_ex returning non-zero (closed/error)
        mock_instance = mock_socket.return_value.__enter__.return_value
        mock_instance.connect_ex.return_value = 111 # Connection refused
        
        port, is_open = self.scout.scan_port(81)
        self.assertFalse(is_open)

    def test_invalid_host(self):
        with patch('socket.gethostbyname', side_effect=socket.gaierror):
            scout = NetScout('invalid.host.xyz')
            self.assertIsNone(scout.ip)
            port, is_open = scout.scan_port(80)
            self.assertFalse(is_open)

if __name__ == '__main__':
    unittest.main()
