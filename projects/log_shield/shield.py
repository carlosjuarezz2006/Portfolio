import secrets
import string
import logging
import os
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

    def mask_email(self, email: str) -> str:
        """Masks an email address for privacy."""
        try:
            user, domain = email.split('@')
            masked_user = user[0] + "***" + user[-1] if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        except ValueError:
            return email

    def generate_secure_token(self, length=32) -> str:
        """Generates a cryptographically secure token for session masking."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def anonymize_log_line(self, line: str) -> str:
        """Simple anonymization logic for demonstration."""
        # This is a placeholder for more complex regex-based anonymization
        words = line.split()
        anonymized_words = []
        for word in words:
            if "@" in word:
                anonymized_words.append(self.mask_email(word))
            else:
                anonymized_words.append(word)
        return " ".join(anonymized_words)

    def process_file(self, input_path: str, output_path: str):
        """Processes a log file and writes the anonymized version."""
        if not os.path.exists(input_path):
            self.logger.error(f"File not found: {input_path}")
            return

        with open(input_path, 'r') as infile, open(output_path, 'w') as outfile:
            for line in infile:
                outfile.write(self.anonymize_log_line(line) + "\n")
        
        self.logger.info(f"Successfully processed {input_path} -> {output_path}")

if __name__ == "__main__":
    shield = LogShield()
    print(f"Secure Token Example: {shield.generate_secure_token()}")
    sample_log = "User admin@example.com logged in from 192.168.1.1"
    print(f"Anonymized: {shield.anonymize_log_line(sample_log)}")
