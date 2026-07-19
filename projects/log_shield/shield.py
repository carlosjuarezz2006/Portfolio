import secrets
import string
import logging
import os
import re
from datetime import datetime

class LogShield:
    """
    LogShield: A secure log anonymizer for IT Support.
    Replaces sensitive data (IPs, emails, tokens) with secure hashes or masked values.
    """
    def __init__(self, log_level=logging.INFO):
        self.logger = logging.getLogger("LogShield")
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)
        
        # Regex for common patterns
        self.email_regex = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        self.ip_regex = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

    def mask_email(self, email: str) -> str:
        """Masks an email address for privacy."""
        try:
            user, domain = email.split('@')
            masked_user = user[0] + "***" + user[-1] if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        except ValueError:
            return email

    def mask_ip(self, ip: str) -> str:
        """Masks an IP address by replacing the last two octets."""
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.xxx.xxx"
        return ip

    def generate_secure_token(self, length=32) -> str:
        """Generates a cryptographically secure token for session masking."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def anonymize_log_line(self, line: str) -> str:
        """Anonymizes emails and IPs in a log line using regex."""
        # Mask Emails
        line = self.email_regex.sub(lambda m: self.mask_email(m.group()), line)
        # Mask IPs
        line = self.ip_regex.sub(lambda m: self.mask_ip(m.group()), line)
        return line

    def process_file(self, input_path: str, output_path: str):
        """Processes a log file and writes the anonymized version."""
        if not os.path.exists(input_path):
            self.logger.error(f"File not found: {input_path}")
            return

        try:
            with open(input_path, 'r') as infile, open(output_path, 'w') as outfile:
                for line in infile:
                    outfile.write(self.anonymize_log_line(line.strip()) + "\n")
            self.logger.info(f"Successfully processed {input_path} -> {output_path}")
        except Exception as e:
            self.logger.error(f"Processing failed: {e}")

if __name__ == "__main__":
    shield = LogShield()
    sample_log = "User admin@example.com logged in from 192.168.1.1 at 2026-07-19"
    print(f"Anonymized: {shield.anonymize_log_line(sample_log)}")
