import unittest
from unittest.mock import patch, MagicMock
from sentinel import CertSentinel
import datetime

class TestCertSentinel(unittest.TestCase):
    def setUp(self):
        self.sentinel = CertSentinel()

    @patch('socket.create_connection')
    @patch('ssl.SSLContext.wrap_socket')
    def test_get_cert_info_success(self, mock_wrap, mock_connect):
        # Mock certificate data
        mock_ssock = MagicMock()
        mock_wrap.return_value.__enter__.return_value = mock_ssock
        
        # Future date for expiration
        future_date = (datetime.datetime.utcnow() + datetime.timedelta(days=30))
        expire_str = future_date.strftime('%b %d %H:%M:%S %Y GMT')
        
        mock_ssock.getpeercert.return_value = {
            'notAfter': expire_str,
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),)
        }

        info = self.sentinel.get_cert_info("example.com")
        
        self.assertIsNotNone(info)
        self.assertEqual(info['issuer'], 'Test CA')
        self.assertEqual(info['days_left'], 29) # 30 - 1 approximately

    def test_health_logic(self):
        # Mocking get_cert_info to test check_health logic
        with patch.object(CertSentinel, 'get_cert_info') as mock_get:
            # Healthy case
            mock_get.return_value = {'days_left': 20}
            self.assertIn("🟢", self.sentinel.check_health("test.com"))
            
            # Warning case
            mock_get.return_value = {'days_left': 5}
            self.assertIn("🟠", self.sentinel.check_health("test.com"))
            
            # Expired case
            mock_get.return_value = {'days_left': -1}
            self.assertIn("🔴 EXPIRED", self.sentinel.check_health("test.com"))

if __name__ == '__main__':
    unittest.main()
