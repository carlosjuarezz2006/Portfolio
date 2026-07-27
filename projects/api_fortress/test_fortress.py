import unittest
from unittest.mock import patch, Mock, MagicMock
from fortress import APIFortress, EndpointHealth, MonitorReport
import requests
import json
import os
import time


class TestAPIFortressCore(unittest.TestCase):
    """Test suite for APIFortress core functionality."""

    def setUp(self):
        self.fortress = APIFortress()

    @patch('requests.Session.request')
    def test_check_endpoint_success(self, mock_request):
        """Mock a successful API response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"status": "ok"}'
        mock_response.text = '{"status": "ok"}'
        mock_request.return_value = mock_response

        result = self.fortress.check_endpoint("https://api.success.com")

        self.assertTrue(result.is_up)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.url, "https://api.success.com")
        self.assertGreater(result.response_size, 0)
        self.assertEqual(result.error_message, "")
        self.assertGreater(len(self.fortress.history), 0)

    @patch('requests.Session.request')
    def test_check_endpoint_failure(self, mock_request):
        """Mock a connection error."""
        mock_request.side_effect = requests.exceptions.ConnectionError()

        result = self.fortress.check_endpoint("https://api.fail.com")

        self.assertFalse(result.is_up)
        self.assertIsNone(result.status_code)
        self.assertIn("Connection error", result.error_message)

    @patch('requests.Session.request')
    def test_check_endpoint_timeout(self, mock_request):
        """Mock a timeout."""
        mock_request.side_effect = requests.exceptions.Timeout()

        result = self.fortress.check_endpoint("https://api.slow.com")

        self.assertFalse(result.is_up)
        self.assertIn("timed out", result.error_message.lower())

    @patch('requests.Session.request')
    def test_expected_status_match(self, mock_request):
        """Test endpoint check with expected status code."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'ok'
        mock_response.text = 'ok'
        mock_request.return_value = mock_response

        result = self.fortress.check_endpoint("https://api.test", expected_status=200)
        self.assertTrue(result.is_up)

    @patch('requests.Session.request')
    def test_expected_status_mismatch(self, mock_request):
        """Test endpoint check with mismatched expected status."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.content = b'error'
        mock_response.text = 'error'
        mock_request.return_value = mock_response

        result = self.fortress.check_endpoint("https://api.test", expected_status=200)
        self.assertFalse(result.is_up)
        self.assertIn("Expected status", result.error_message)

    @patch('requests.Session.request')
    def test_expected_text_found(self, mock_request):
        """Test endpoint check with expected text present."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'Hello World'
        mock_response.text = 'Hello World'
        mock_request.return_value = mock_response

        result = self.fortress.check_endpoint(
            "https://api.test", expected_text="World"
        )
        self.assertTrue(result.is_up)

    @patch('requests.Session.request')
    def test_expected_text_not_found(self, mock_request):
        """Test endpoint check with expected text absent."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'Goodbye'
        mock_response.text = 'Goodbye'
        mock_request.return_value = mock_response

        result = self.fortress.check_endpoint(
            "https://api.test", expected_text="Hello"
        )
        self.assertFalse(result.is_up)

    @patch('requests.Session.request')
    def test_bulk_monitor(self, mock_request):
        """Test concurrent bulk monitoring."""
        def mock_response_factory(url):
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b'ok'
            mock_resp.text = 'ok'
            return mock_resp

        mock_request.side_effect = mock_response_factory

        urls = ["https://api1.test", "https://api2.test", "https://api3.test"]
        results = self.fortress.bulk_monitor(urls)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.is_up for r in results))

        # Check sorted by URL
        self.assertEqual(results[0].url, "https://api1.test")
        self.assertEqual(results[2].url, "https://api3.test")

    @patch('requests.Session.request')
    def test_bulk_monitor_with_failures(self, mock_request):
        """Test bulk monitoring with some failures."""
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                raise requests.exceptions.ConnectionError()
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b'ok'
            mock_resp.text = 'ok'
            return mock_resp

        mock_request.side_effect = side_effect

        urls = ["https://api1.test", "https://api2.test", "https://api3.test"]
        results = self.fortress.bulk_monitor(urls)
        self.assertEqual(len(results), 3)
        up_count = sum(1 for r in results if r.is_up)
        self.assertEqual(up_count, 2)

    @patch('requests.Session.request')
    def test_retry_success_on_second_attempt(self, mock_request):
        """Test retry logic succeeds on second attempt."""
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise requests.exceptions.ConnectionError()
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b'ok'
            mock_resp.text = 'ok'
            return mock_resp

        mock_request.side_effect = side_effect

        result = self.fortress.monitor_with_retry(
            "https://api.test", retries=2, backoff=0.1
        )
        self.assertTrue(result.is_up)
        self.assertEqual(call_count[0], 2)

    @patch('requests.Session.request')
    def test_retry_all_fail(self, mock_request):
        """Test retry logic when all attempts fail."""
        mock_request.side_effect = requests.exceptions.ConnectionError()

        result = self.fortress.monitor_with_retry(
            "https://api.test", retries=2, backoff=0.1
        )
        self.assertFalse(result.is_up)

    def test_get_report_empty(self):
        """Test report generation with no data."""
        report = self.fortress.get_report()
        self.assertEqual(report.total_endpoints, 0)
        self.assertEqual(report.total_checks, 0)

    def test_get_report_with_data(self):
        """Test report generation with recorded data."""
        self.fortress.history = [
            EndpointHealth("url1", 200, 100.0, True, 100, "", 0.0),
            EndpointHealth("url2", 200, 50.0, True, 200, "", 0.0),
            EndpointHealth("url3", 500, 200.0, False, 50, "Error", 0.0),
        ]

        report = self.fortress.get_report()
        self.assertEqual(report.total_endpoints, 3)
        self.assertEqual(report.endpoints_up, 2)
        self.assertEqual(report.endpoints_down, 1)
        self.assertAlmostEqual(report.uptime_percentage, 66.666, places=2)
        self.assertAlmostEqual(report.average_latency, 116.666, places=2)
        self.assertEqual(report.max_latency, 200.0)
        self.assertEqual(report.min_latency, 50.0)

    def test_get_summary(self):
        """Test summary generation."""
        self.fortress.history = [
            EndpointHealth("url1", 200, 100.0, True, 100, "", 0.0),
            EndpointHealth("url2", 500, 200.0, False, 50, "Error", 0.0),
        ]

        summary = self.fortress.get_summary()
        self.assertEqual(summary['total_checks'], 2)
        self.assertEqual(summary['endpoints_up'], 1)
        self.assertEqual(summary['endpoints_down'], 1)
        self.assertEqual(summary['uptime_percentage'], 50.0)

    def test_save_report(self):
        """Test saving report to JSON."""
        self.fortress.history = [
            EndpointHealth("url1", 200, 100.0, True, 100, "", 0.0),
        ]
        self.fortress.save_report("test_health.json")
        self.assertTrue(os.path.exists("test_health.json"))
        with open("test_health.json") as f:
            data = json.load(f)
        self.assertIn("report", data)
        self.assertIn("endpoints", data)
        self.assertEqual(len(data["endpoints"]), 1)
        os.remove("test_health.json")


if __name__ == '__main__':
    unittest.main()