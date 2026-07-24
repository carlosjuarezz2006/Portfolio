import unittest
import os
import json
from shield import LogShield

class TestLogShield(unittest.TestCase):
    def setUp(self):
        self.shield = LogShield()

    def test_mask_email(self):
        self.assertEqual(self.shield.mask_email("carlos@example.com"), "c***s@example.com")
        self.assertEqual(self.shield.mask_email("a@b.com"), "***@b.com")

    def test_mask_ip(self):
        self.assertEqual(self.shield.mask_ip("192.168.1.1"), "192.168.xxx.xxx")
        self.assertEqual(self.shield.mask_ip("10.0.0.255"), "10.0.xxx.xxx")

    def test_mask_phone(self):
        self.assertEqual(self.shield.mask_phone("+1-555-123-4567"), "***4567")
        self.assertEqual(self.shield.mask_phone("123456"), "***3456")

    def test_mask_credit_card(self):
        self.assertEqual(self.shield.mask_credit_card("4111-1111-1111-1111"), "****-****-****-1111")
        self.assertEqual(self.shield.mask_credit_card("1234"), "****")

    def test_mask_token(self):
        token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        masked = self.shield.mask_token(token)
        self.assertIn("...", masked)
        # Short token should be fully masked
        self.assertEqual(self.shield.mask_token("short"), "****")

    def test_token_length(self):
        token = self.shield.generate_secure_token(64)
        self.assertEqual(len(token), 64)
        token_32 = self.shield.generate_secure_token(32)
        self.assertEqual(len(token_32), 32)

    def test_anonymize_line(self):
        line = "Contact support@company.com for help"
        result = self.shield.anonymize_log_line(line)
        self.assertIn("s***t@company.com", result)

    def test_anonymize_full_line(self):
        """Test anonymizing a line with all PII types."""
        line = (
            "User admin@example.com from 192.168.1.1 called +1-555-123-4567 "
            "with card 4111-1111-1111-1111 token ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        )
        result = self.shield.anonymize_log_line(line)
        # Emails should be masked
        self.assertIn("***@example.com", result)
        # IPs should be masked
        self.assertIn("192.168.xxx.xxx", result)
        # Phone should be masked
        self.assertIn("***4567", result)
        # Credit card should be masked
        self.assertIn("****-****-****-1111", result)
        # Token should be masked
        self.assertIn("...", result)

    def test_process_file(self):
        """Test processing a file with PII data."""
        input_file = "test_input.log"
        output_file = "test_output.log"
        with open(input_file, "w") as f:
            f.write("admin@example.com 192.168.1.1\n")
            f.write("normal line without PII\n")
        
        try:
            stats = self.shield.process_file(input_file, output_file)
            self.assertEqual(stats["status"], "success")
            self.assertEqual(stats["lines"], 2)
            self.assertGreater(stats["emails"], 0)
            self.assertGreater(stats["ips"], 0)
            
            with open(output_file) as f:
                content = f.read()
            self.assertIn("***@example.com", content)
            self.assertIn("192.168.xxx.xxx", content)
        finally:
            if os.path.exists(input_file):
                os.remove(input_file)
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_process_file_not_found(self):
        """Test processing a non-existent file."""
        result = self.shield.process_file("nonexistent.log", "out.log")
        self.assertEqual(result["status"], "error")

    def test_batch_process(self):
        """Test batch processing multiple files."""
        input1 = "batch1.log"
        input2 = "batch2.log"
        with open(input1, "w") as f:
            f.write("email@test.com\n")
        with open(input2, "w") as f:
            f.write("192.168.1.1\n")
        
        try:
            results = self.shield.batch_process([(input1, "batch1_out.log"), (input2, "batch2_out.log")])
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["status"], "success")
            self.assertEqual(results[1]["status"], "success")
        finally:
            for f in [input1, input2, "batch1_out.log", "batch2_out.log"]:
                if os.path.exists(f):
                    os.remove(f)


if __name__ == '__main__':
    unittest.main()