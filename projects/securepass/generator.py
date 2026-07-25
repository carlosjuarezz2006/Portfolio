"""
SecurePass Generator
====================
A cryptographically secure password generator with entropy calculation,
strength evaluation, passphrase generation, and bulk mode.

Grok Build Standards:
- Cryptographic Security: Uses Python's `secrets` module exclusively
- OOP: Clean single-responsibility classes with type hints
- Documentation: Full docstrings, logging, error handling
"""

import secrets
import string
import math
import logging
from typing import List, Optional, Tuple

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SecurePass")


class PasswordGenerator:
    """
    Professional password generator with cryptographically secure entropy.

    Generates random passwords that meet configurable complexity requirements
    using Python's `secrets` module for all randomness.

    Args:
        length: Password length (minimum 8).
        use_digits: Include numeric digits.
        use_special: Include special/punctuation characters.
        use_uppercase: Include uppercase letters.

    Raises:
        ValueError: If length < 8 or no character sets selected.
    """

    def __init__(self, length: int = 16, use_digits: bool = True,
                 use_special: bool = True, use_uppercase: bool = True):
        if length < 8:
            raise ValueError("Password length must be at least 8 characters for security.")

        if not any([use_digits, use_special, use_uppercase]):
            raise ValueError("At least one character set must be selected.")

        self.length = length
        self.use_digits = use_digits
        self.use_special = use_special
        self.use_uppercase = use_uppercase

    def _build_alphabet(self) -> str:
        """Build the character alphabet based on selected options."""
        chars = string.ascii_lowercase
        if self.use_uppercase:
            chars += string.ascii_uppercase
        if self.use_digits:
            chars += string.digits
        if self.use_special:
            chars += string.punctuation
        return chars

    def generate(self) -> str:
        """
        Generates a cryptographically secure random password.

        The password is guaranteed to contain at least one character
        from each selected character set.

        Returns:
            A secure random password string.
        """
        chars = self._build_alphabet()

        # Cryptographically secure selection with validation
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(self.length))

            # Validate: ensure at least one of each requested type
            if self.use_digits and not any(c.isdigit() for c in password):
                continue
            if self.use_special and not any(c in string.punctuation for c in password):
                continue
            if self.use_uppercase and not any(c.isupper() for c in password):
                continue

            return password

    def calculate_entropy(self, password: str) -> float:
        """
        Calculate the Shannon entropy of a password in bits.

        Args:
            password: The password string to evaluate.

        Returns:
            Entropy value in bits (higher = stronger).
        """
        pool_size = 0
        if any(c.islower() for c in password):
            pool_size += 26
        if any(c.isupper() for c in password):
            pool_size += 26
        if any(c.isdigit() for c in password):
            pool_size += 10
        if any(c in string.punctuation for c in password):
            pool_size += 32

        if pool_size == 0:
            return 0.0

        return len(password) * math.log2(pool_size)

    def evaluate_strength(self, password: str) -> Tuple[str, float]:
        """
        Evaluate password strength based on entropy.

        Args:
            password: The password to evaluate.

        Returns:
            Tuple of (strength_label, entropy_bits).
            Labels: "Very Weak", "Weak", "Moderate", "Strong", "Very Strong"
        """
        entropy = self.calculate_entropy(password)

        if entropy < 40:
            return "Very Weak", entropy
        elif entropy < 60:
            return "Weak", entropy
        elif entropy < 80:
            return "Moderate", entropy
        elif entropy < 100:
            return "Strong", entropy
        else:
            return "Very Strong", entropy

    def generate_bulk(self, count: int = 5) -> List[Tuple[str, str, float]]:
        """
        Generate multiple passwords with strength evaluation.

        Args:
            count: Number of passwords to generate.

        Returns:
            List of (password, strength_label, entropy_bits) tuples.
        """
        results = []
        for _ in range(count):
            pwd = self.generate()
            label, entropy = self.evaluate_strength(pwd)
            results.append((pwd, label, entropy))
        return results


class PassphraseGenerator:
    """
    Cryptographically secure passphrase generator using word lists.

    Generates memorable yet secure passphrases by combining words
    from a built-in word list with optional separators.

    Args:
        word_count: Number of words in the passphrase (minimum 3).
        separator: Character between words (default: '-').
        capitalize: Capitalize each word for readability.
        append_digit: Append a random digit for extra entropy.
    """

    # 100 common English words suitable for passphrases
    WORDS = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
        "golf", "hotel", "india", "juliet", "kilo", "lima", "mike",
        "november", "oscar", "papa", "quebec", "romeo", "sierra",
        "tango", "uniform", "victor", "whiskey", "xray", "yankee",
        "zulu", "bridge", "cloud", "dragon", "eagle", "forest",
        "garden", "harbor", "island", "jewel", "knight", "lighthouse",
        "mountain", "nebula", "ocean", "planet", "quartz", "river",
        "sunset", "temple", "umbrella", "valley", "winter", "crystal",
        "aurora", "blossom", "cascade", "meadow", "pebble", "thunder",
        "breeze", "canyon", "ember", "falcon", "glacier", "horizon",
        "jasmine", "lagoon", "marble", "noble", "orchid", "puzzle",
        "quantum", "raven", "sapphire", "tornado", "violet", "willow",
        "zenith", "archer", "bamboo", "cosmos", "dolphin", "fossil",
        "gondola", "harvest", "jupiter", "karma", "liberty", "magnet",
        "needle", "olympic", "penguin", "radiant", "saturn", "tribune",
        "utopia", "vortex", "waffle", "zenith", "acorn", "bliss"
    ]

    def __init__(self, word_count: int = 4, separator: str = "-",
                 capitalize: bool = True, append_digit: bool = True):
        if word_count < 3:
            raise ValueError("Passphrase must contain at least 3 words for security.")

        self.word_count = word_count
        self.separator = separator
        self.capitalize = capitalize
        self.append_digit = append_digit

    def generate(self) -> str:
        """
        Generate a cryptographically secure passphrase.

        Returns:
            A secure passphrase string.
        """
        words = [secrets.choice(self.WORDS) for _ in range(self.word_count)]

        if self.capitalize:
            words = [w.capitalize() for w in words]

        passphrase = self.separator.join(words)

        if self.append_digit:
            passphrase += str(secrets.randbelow(100))

        return passphrase

    def calculate_entropy(self) -> float:
        """
        Calculate the theoretical entropy of the generated passphrase.

        Returns:
            Entropy in bits.
        """
        word_entropy = math.log2(len(self.WORDS)) * self.word_count
        if self.append_digit:
            word_entropy += math.log2(100)
        return word_entropy


if __name__ == "__main__":
    # Demo: Password generation
    print("=" * 50)
    print("  SecurePass Generator")
    print("=" * 50)

    gen = PasswordGenerator(length=20)
    pwd = gen.generate()
    strength, entropy = gen.evaluate_strength(pwd)
    print(f"\nPassword: {pwd}")
    print(f"Strength: {strength} ({entropy:.1f} bits of entropy)")

    # Bulk generation
    print("\nBulk Passwords:")
    for pwd, label, ent in gen.generate_bulk(3):
        print(f"  {pwd}  [{label} - {ent:.1f} bits]")

    # Passphrase demo
    phrase_gen = PassphraseGenerator()
    phrase = phrase_gen.generate()
    print(f"\nPassphrase: {phrase}")
    print(f"Entropy: {phrase_gen.calculate_entropy():.1f} bits")