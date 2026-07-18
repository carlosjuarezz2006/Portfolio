import unittest
from shield import LogShield

class TestLogShield(unittest.TestCase):
    def setUp(self):
        self.shield = LogShield()

    def test_mask_email(self):
        self.assertEqual(self.shield.mask_email("carlos@example.com"), "c***s@example.com")
        self.assertEqual(self.shield.mask_email("a@b.com"), "***@b.com")

    def test_token_length(self):
        token = self.shield.generate_secure_token(64)
        self.assertEqual(len(token), 64)

    def test_anonymize_line(self):
        line = "Contact support@company.com for help"
        self.assertIn("s***t@company.com", self.shield.anonymize_log_line(line))

if __name__ == '__main__':
    unittest.main()
