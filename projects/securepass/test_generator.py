import unittest
from generator import PasswordGenerator, PassphraseGenerator
import string


class TestPasswordGenerator(unittest.TestCase):
    """Test suite for the PasswordGenerator class."""

    def test_length(self):
        """Generated password should be exactly the requested length."""
        gen = PasswordGenerator(length=12)
        self.assertEqual(len(gen.generate()), 12)

    def test_digits(self):
        """Password should contain at least one digit when requested."""
        gen = PasswordGenerator(length=20, use_digits=True, use_special=False, use_uppercase=False)
        password = gen.generate()
        self.assertTrue(any(c.isdigit() for c in password))

    def test_special(self):
        """Password should contain at least one special character when requested."""
        gen = PasswordGenerator(length=20, use_digits=False, use_special=True, use_uppercase=False)
        password = gen.generate()
        self.assertTrue(any(c in string.punctuation for c in password))

    def test_uppercase(self):
        """Password should contain at least one uppercase letter when requested."""
        gen = PasswordGenerator(length=20, use_digits=False, use_special=False, use_uppercase=True)
        password = gen.generate()
        self.assertTrue(any(c.isupper() for c in password))

    def test_minimum_length(self):
        """Length below 8 should raise ValueError."""
        with self.assertRaises(ValueError):
            PasswordGenerator(length=4)

    def test_entropy_calculation(self):
        """Entropy should be calculated correctly."""
        gen = PasswordGenerator(length=16)
        entropy = gen.calculate_entropy()
        # 16 chars from ~72 possible chars = 16 * log2(72) ≈ 16 * 6.17 ≈ 98.7
        self.assertGreater(entropy, 90)
        self.assertLess(entropy, 110)

    def test_strength_evaluation(self):
        """Strength labels should be correct for different entropy values."""
        gen = PasswordGenerator(length=8)
        _, label, _ = gen.generate_with_strength()
        # 8 chars with lowercase only = 8 * log2(26) ≈ 37.6 bits -> Weak
        self.assertEqual(label, "Weak")

    def test_bulk_generation(self):
        """Bulk generation should return the requested number of passwords."""
        passwords = PasswordGenerator(length=12).generate_bulk(5)
        self.assertEqual(len(passwords), 5)

    def test_empty_character_set(self):
        """No character sets selected should raise ValueError."""
        with self.assertRaises(ValueError):
            PasswordGenerator(length=12, use_digits=False, use_special=False, use_uppercase=False).generate()

    def test_passphrase_word_count(self):
        """Passphrase should contain the correct number of words."""
        phrase_gen = PassphraseGenerator(word_count=6)
        phrase = phrase_gen.generate()
        words = phrase.split("-")
        self.assertEqual(len(words), 6)

    def test_passphrase_entropy(self):
        """Passphrase entropy should be positive."""
        phrase_gen = PassphraseGenerator(word_count=4)
        entropy = phrase_gen.calculate_entropy()
        self.assertGreater(entropy, 0)

    def test_passphrase_no_duplicates(self):
        """Passphrase words should be unique."""
        phrase_gen = PassphraseGenerator(word_count=4)
        phrase = phrase_gen.generate()
        words = phrase.split("-")
        self.assertEqual(len(words), len(set(words)))


if __name__ == '__main__':
    unittest.main()