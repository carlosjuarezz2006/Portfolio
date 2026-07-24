import secrets
import string
import logging
import os
import re
from datetime import datetime
from typing import List, Dict, Optional

class LogShield:
    """
    LogShield: A secure log anonymizer for IT Support.
    Replaces sensitive data (IPs, emails, tokens, phone numbers, credit cards)
    with secure hashes or masked values.
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
        # Phone numbers: +XX XXXXXXXXXX or (XXX) XXX-XXXX or XXX-XXX-XXXX
        self.phone_regex = re.compile(r'(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b')
        # Credit card numbers (16-digit patterns, optionally grouped)
        self.cc_regex = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
        # API keys / tokens: alphanumeric strings 32+ chars preceded by common key names
        self.token_regex = re.compile(r'\b([A-Za-z0-9_-]{32,})\b')

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

    def mask_phone(self, phone: str) -> str:
        """Masks a phone number, keeping only the last 4 digits."""
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 4:
            return f"***{digits[-4:]}"
        return "***"

    def mask_credit_card(self, cc: str) -> str:
        """Masks a credit card number, showing only the last 4 digits."""
        digits = re.sub(r'\D', '', cc)
        if len(digits) >= 4:
            return f"****-****-****-{digits[-4:]}"
        return "****"

    def mask_token(self, token: str) -> str:
        """Masks a long alphanumeric token, keeping first 4 and last 4 chars."""
        if len(token) <= 8:
            return "****"
        return f"{token[:4]}...{token[-4:]}"

    def generate_secure_token(self, length=32) -> str:
        """Generates a cryptographically secure token for session masking."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def anonymize_log_line(self, line: str) -> str:
        """Anonymizes emails, IPs, phones, credit cards, and tokens in a log line."""
        # Mask Emails
        line = self.email_regex.sub(lambda m: self.mask_email(m.group()), line)
        # Mask IPs
        line = self.ip_regex.sub(lambda m: self.mask_ip(m.group()), line)
        # Mask Phone Numbers
        line = self.phone_regex.sub(lambda m: self.mask_phone(m.group()), line)
        # Mask Credit Cards
        line = self.cc_regex.sub(lambda m: self.mask_credit_card(m.group()), line)
        # Mask Long Tokens (not inside already masked content)
        line = self.token_regex.sub(lambda m: self.mask_token(m.group()), line)
        return line

    def process_file(self, input_path: str, output_path: str) -> Dict:
        """
        Processes a log file and writes the anonymized version.
        Returns a stats dictionary with counts of masked items.
        """
        if not os.path.exists(input_path):
            self.logger.error(f"File not found: {input_path}")
            return {"status": "error", "message": f"File not found: {input_path}"}

        stats = {"emails": 0, "ips": 0, "phones": 0, "cards": 0, "tokens": 0, "lines": 0}
        
        try:
            with open(input_path, 'r') as infile, open(output_path, 'w') as outfile:
                for line in infile:
                    original = line.strip()
                    anonymized = self.anonymize_log_line(original)
                    outfile.write(anonymized + "\n")
                    stats["lines"] += 1
                    if original != anonymized:
                        # Count by type (approximate from regex matches)
                        stats["emails"] += len(self.email_regex.findall(original))
                        stats["ips"] += len(self.ip_regex.findall(original))
                        stats["phones"] += len(self.phone_regex.findall(original))
                        stats["cards"] += len(self.cc_regex.findall(original))
                        stats["tokens"] += len(self.token_regex.findall(original))
            self.logger.info(
                f"Processed {input_path} -> {output_path}: "
                f"{stats['lines']} lines, "
                f"{stats['emails']} emails, {stats['ips']} IPs, "
                f"{stats['phones']} phones, {stats['cards']} cards, "
                f"{stats['tokens']} tokens masked"
            )
            stats["status"] = "success"
            return stats
        except Exception as e:
            self.logger.error(f"Processing failed: {e}")
            return {"status": "error", "message": str(e)}

    def batch_process(self, file_pairs: List[tuple]) -> List[Dict]:
        """
        Processes multiple file pairs [(input, output), ...].
        Returns a list of stats dictionaries.
        """
        results = []
        for input_path, output_path in file_pairs:
            result = self.process_file(input_path, output_path)
            results.append(result)
        return results


if __name__ == "__main__":
    shield = LogShield()
    sample_log = (
        "User admin@example.com logged in from 192.168.1.1 at 2026-07-19. "
        "Phone: +1-555-123-4567. CC: 4111-1111-1111-1111. "
        "Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    )
    print(f"Original: {sample_log}")
    print(f"Anonymized: {shield.anonymize_log_line(sample_log)}")