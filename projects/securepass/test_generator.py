import unittest
from generator import PasswordGenerator
import string

class TestPasswordGenerator(unittest.TestCase):
    def test_length(self):
        gen = PasswordGenerator(length=12)
        self.assertEqual(len(gen.generate()), 12)

    def test_digits(self):
        gen = PasswordGenerator(length=20, use_digits=True, use_special=False, use_uppercase=False)
        password = gen.generate()
        self.assertTrue(any(c.isdigit() for c in password))

    def test_special(self):
        gen = PasswordGenerator(length=20, use_digits=False, use_special=True, use_uppercase=False)
        password = gen.generate()
        self.assertTrue(any(c in string.punctuation for c in password))

    def test_minimum_length(self):
        with self.assertRaises(ValueError):
            PasswordGenerator(length=4)

if __name__ == '__main__':
    unittest.main()
