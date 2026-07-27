import unittest
import os
import json
import tempfile
from shield import LogShield, AnonymizedResult


class TestLogShield(unittest.TestCase):
    """Test suite for LogShield log anonymizer."""

    def setUp(self):
        self.shield = LogShield()

    def test_mask_email_standard(self):
        """Standard email masking."""
        self.assertEqual(
            self.shield.mask_email("carlos@example.com"),
            "c***s@example.com"
        )

    def test_mask_email_short(self):
        """Short email should be fully masked before @."""
        self.assertEqual(
            self.shield.mask_email("a@b.com"),
            "***@b.com"
        )

    def test_mask_email_two_char(self):
        """Two-char local part should be fully masked."""
        self.assertEqual(
            self.shield.mask_email("ab@test.com"),
            "***@test.com"
        )

    def test_mask_ipv4_standard(self):
        self.assertEqual(
            self.shield.mask_ipv4("192.168.1.1"),
            "192.168.xxx.xxx"
        )

    def test_mask_ipv4_all_zeros(self):
        self.assertEqual(
            self.shield.mask_ipv4("0.0.0.0"),
            "0.0.xxx.xxx"
        )

    def test_mask_phone_standard(self):
        self.assertEqual(
            self.shield.mask_phone("+1-555-123-4567"),
            "***4567"
        )

    def test_mask_phone_short(self):
        self.assertEqual(self.shield.mask_phone("123456"), "***3456")

    def test_mask_credit_card_standard(self):
        self.assertEqual(
            self.shield.mask_credit_card("4111-1111-1111-1111"),
            "****-****-****-1111"
        )

    def test_mask_credit_card_continuous(self):
        self.assertEqual(
            self.shield.mask_credit_card("4111111111111111"),
            "************1111"
        )

    def test_mask_token_long(self):
        """Long token should show first 4 and last 4 chars."""
        token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        masked = self.shield.mask_token(token)
        self.assertIn("...", masked)
        self.assertTrue(masked.endswith("7890"))

    def test_mask_token_short(self):
        """Short token should be fully masked."""
        self.assertEqual(self.shield.mask_token("short"), "****")

    def test_mask_token_exact_8(self):
        """8-char token should be fully masked."""
        self.assertEqual(self.shield.mask_token("12345678"), "****")

    def test_mask_url_with_query(self):
        """URL with query string should have query masked."""
        url = "https://example.com/login?token=secret123"
        self.assertEqual(
            self.shield.mask_url(url),
            "https://example.com/login?***masked***"
        )

    def test_mask_url_no_query(self):
        """URL without query string should remain unchanged."""
        url = "https://example.com/page"
        self.assertEqual(self.shield.mask_url(url), url)

    def test_mask_mac_colon(self):
        """MAC address with colons should be masked."""
        mac = "00:1a:2b:3c:4d:5e"
        self.assertEqual(
            self.shield.mask_mac(mac),
            "00:1a:2b:xx:xx:xx"
        )

    def test_mask_mac_dash(self):
        """MAC address with dashes should be masked."""
        mac = "00-1A-2B-3C-4D-5E"
        self.assertEqual(
            self.shield.mask_mac(mac),
            "00-1A-2B-xx-xx-xx"
        )

    def test_mask_file_path_unix(self):
        """Unix file path should be masked to ***/filename."""
        path = "/home/user/.ssh/id_rsa"
        self.assertEqual(
            self.shield.mask_file_path(path),
            "***/id_rsa"
        )

    def test_mask_file_path_short(self):
        """Short path should remain unchanged."""
        self.assertEqual(
            self.shield.mask_file_path("file.txt"),
            "file.txt"
        )

    def test_anonymize_log_line_full(self):
        """Full log line with all patterns should be anonymized."""
        original = (
            "User admin@example.com from 192.168.1.1 "
            "phone +1-555-123-4567 "
            "CC 4111-1111-1111-1111 "
            "token ghp_abcdefghijklmnopqrstuvwxyz1234567890 "
            "url https://example.com/login?token=secret "
            "MAC 00:1a:2b:3c:4d:5e "
            "path /home/user/file.txt"
        )
        result = self.shield.anonymize_log_line(original)
        self.assertIn("***@example.com", result)
        self.assertIn("192.168.xxx.xxx", result)
        self.assertIn("***4567", result)
        self.assertIn("****-****-****-1111", result)
        self.assertIn("...", result)
        self.assertIn("***masked***", result)
        self.assertIn("xx:xx:xx", result)
        self.assertIn("***/file.txt", result)
        # Original sensitive data should not appear
        self.assertNotIn("admin@example.com", result)
        self.assertNotIn("192.168.1.1", result)

    def test_anonymize_log_line_no_patterns(self):
        """Line without patterns should remain unchanged."""
        line = "This is a normal log line with no sensitive data."
        result = self.shield.anonymize_log_line(line)
        self.assertEqual(result, line)

    def test_anonymize_log_line_empty(self):
        """Empty line should remain empty."""
        self.assertEqual(self.shield.anonymize_log_line(""), "")

    def test_anonymize_stream(self):
        """Streaming mode should yield anonymized lines."""
        lines = [
            "User admin@example.com logged in\n",
            "Normal log line\n",
            "CC 4111-1111-1111-1111\n",
        ]
        results = list(self.shield.anonymize_stream(iter(lines)))
        self.assertEqual(len(results), 3)
        self.assertIn("***@example.com", results[0])
        self.assertEqual(results[1], "Normal log line\n")
        self.assertIn("****-****-****-1111", results[2])

    def test_process_file(self):
        """Test processing a file with sensitive data."""
        input_file = "test_input.log"
        output_file = "test_output.log"
        try:
            with open(input_file, "w") as f:
                f.write("User admin@example.com from 192.168.1.1\n")
                f.write("Normal log line\n")

            result = self.shield.process_file(input_file, output_file)
            self.assertEqual(result.status, "success")
            self.assertEqual(result.lines_processed, 2)
            self.assertGreater(result.patterns_masked.get("email", 0), 0)
            self.assertGreater(result.patterns_masked.get("ipv4", 0), 0)

            # Verify output file
            with open(output_file) as f:
                content = f.read()
            self.assertIn("***@example.com", content)
            self.assertIn("192.168.xxx.xxx", content)
        finally:
            for f in [input_file, output_file]:
                if os.path.exists(f):
                    os.remove(f)

    def test_process_file_not_found(self):
        """Test processing a non-existent file."""
        result = self.shield.process_file("nonexistent.log", "out.log")
        self.assertEqual(result.status, "error")
        self.assertIn("not found", result.error_message.lower())

    def test_batch_process(self):
        """Test batch processing multiple files."""
        input1 = "batch1.log"
        input2 = "batch2.log"
        try:
            with open(input1, "w") as f:
                f.write("email@test.com\n")
            with open(input2, "w") as f:
                f.write("192.168.1.1\n")

            results = self.shield.batch_process([
                (input1, "batch1_out.log"),
                (input2, "batch2_out.log"),
            ])
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0].status, "success")
            self.assertEqual(results[1].status, "success")
        finally:
            for f in [input1, input2, "batch1_out.log", "batch2_out.log"]:
                if os.path.exists(f):
                    os.remove(f)

    def test_get_summary(self):
        """Test summary returns expected structure."""
        summary = self.shield.get_summary()
        self.assertIn("patterns_available", summary)
        self.assertIn("total_patterns", summary)
        self.assertGreater(summary["total_patterns"], 0)


if __name__ == '__main__':
    unittest.main()