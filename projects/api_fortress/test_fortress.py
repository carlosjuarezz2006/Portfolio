import unittest
from unittest.mock import patch, Mock
from fortress import APIFortress, EndpointHealth
import requests

class TestAPIFortress(unittest.TestCase):
    def setUp(self):
        self.fortress = APIFortress()

    @patch('requests.request')
    def test_check_endpoint_success(self, mock_request):
        # Mock a successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        url = "https://api.success.com"
        result = self.fortress.check_endpoint(url)
        
        self.assertTrue(result.is_up)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.url, url)
        self.assertGreater(len(self.fortress.history), 0)

    @patch('requests.request')
    def test_check_endpoint_failure(self, mock_request):
        # Mock a failed request (Exception)
        mock_request.side_effect = requests.exceptions.ConnectionError()
        
        url = "https://api.fail.com"
        result = self.fortress.check_endpoint(url)
        
        self.assertFalse(result.is_up)
        self.assertIsNone(result.status_code)

    def test_summary_calculation(self):
        # Manually add health objects to history
        self.fortress.history = [
            EndpointHealth("url1", 200, 100.0, True, 0.0),
            EndpointHealth("url2", 404, 50.0, False, 0.0)
        ]
        
        summary = self.fortress.get_summary()
        self.assertEqual(summary['total_checks'], 2)
        self.assertEqual(summary['uptime_percentage'], 50.0)
        self.assertEqual(summary['average_latency_ms'], 75.0)

if __name__ == '__main__':
    unittest.main()
