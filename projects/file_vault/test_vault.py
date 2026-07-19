import unittest
import os
from vault import FileVault

class TestFileVault(unittest.TestCase):
    def setUp(self):
        self.password = "test-pass"
        self.vault = FileVault(self.password)
        self.test_file = "test_data.txt"
        with open(self.test_file, 'w') as f:
            f.write("Hello World")

    def tearDown(self):
        for f in [self.test_file, self.test_file + ".vault"]:
            if os.path.exists(f):
                os.remove(f)

    def test_encryption_decryption(self):
        self.vault.encrypt_file(self.test_file)
        self.assertTrue(os.path.exists(self.test_file + ".vault"))
        
        # Remove original and decrypt
        os.remove(self.test_file)
        self.vault.decrypt_file(self.test_file + ".vault")
        
        with open(self.test_file, 'r') as f:
            self.assertEqual(f.read(), "Hello World")

    def test_wrong_password(self):
        self.vault.encrypt_file(self.test_file)
        wrong_vault = FileVault("wrong-pass")
        # Should log error and not crash, or we can check if file was NOT restored
        os.remove(self.test_file)
        wrong_vault.decrypt_file(self.test_file + ".vault")
        self.assertFalse(os.path.exists(self.test_file))

if __name__ == '__main__':
    unittest.main()
