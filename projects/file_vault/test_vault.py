import unittest
import os
import tempfile
import shutil
from vault import FileVault, VaultOperation


class TestFileVault(unittest.TestCase):
    """Test suite for FileVault encryption/decryption."""

    def setUp(self):
        self.password = "test-password-1234"
        self.vault = FileVault(self.password)
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test_data.txt")
        with open(self.test_file, 'w') as f:
            f.write("Hello World — This is sensitive data for testing!")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_encryption_creates_vault_file(self):
        """Encryption should create a .vault file."""
        result = self.vault.encrypt_file(self.test_file)
        self.assertTrue(result.success)
        self.assertTrue(os.path.exists(self.test_file + ".vault"))

    def test_encryption_decryption_roundtrip(self):
        """Encrypt then decrypt should restore the original content."""
        self.vault.encrypt_file(self.test_file)
        os.remove(self.test_file)  # Remove original
        self.vault.decrypt_file(self.test_file + ".vault")
        with open(self.test_file, 'r') as f:
            content = f.read()
        self.assertEqual(content, "Hello World — This is sensitive data for testing!")

    def test_wrong_password_fails_gracefully(self):
        """Decrypting with wrong password should fail gracefully."""
        self.vault.encrypt_file(self.test_file)
        os.remove(self.test_file)
        wrong_vault = FileVault("wrong-password-9999")
        result = wrong_vault.decrypt_file(self.test_file + ".vault")
        self.assertFalse(result.success)
        self.assertIn("authentication failed", result.error.lower())

    def test_short_password_raises_error(self):
        """Password shorter than 8 chars should raise ValueError."""
        with self.assertRaises(ValueError):
            FileVault("short")

    def test_empty_password_raises_error(self):
        """Empty password should raise ValueError."""
        with self.assertRaises(ValueError):
            FileVault("")

    def test_file_not_found(self):
        """Encrypting a non-existent file should return failure."""
        result = self.vault.encrypt_file("/nonexistent/file.txt")
        self.assertFalse(result.success)
        self.assertIn("not found", result.error)

    def test_decrypt_non_existent_file(self):
        """Decrypting a non-existent file should return failure."""
        result = self.vault.decrypt_file("/nonexistent/file.vault")
        self.assertFalse(result.success)
        self.assertIn("not found", result.error)

    def test_encrypt_batch(self):
        """Batch encryption should handle multiple files."""
        files = []
        for i in range(3):
            path = os.path.join(self.test_dir, f"test_{i}.txt")
            with open(path, 'w') as f:
                f.write(f"Content {i}")
            files.append(path)

        results = self.vault.encrypt_batch(files)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.success for r in results))

    def test_decrypt_batch(self):
        """Batch decryption should handle multiple vault files."""
        files = []
        for i in range(3):
            path = os.path.join(self.test_dir, f"batch_{i}.txt")
            with open(path, 'w') as f:
                f.write(f"Batch content {i}")
            self.vault.encrypt_file(path)
            os.remove(path)  # Remove originals
            files.append(path + ".vault")

        results = self.vault.decrypt_batch(files)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.success for r in results))

    def test_base64_roundtrip(self):
        """Base64 encrypt/decrypt should work for small data."""
        original = b"API_KEY=sk-abc123def456"
        encrypted = self.vault.encrypt_to_base64(original)
        decrypted = self.vault.decrypt_from_base64(encrypted)
        self.assertEqual(decrypted, original)

    def test_base64_wrong_password(self):
        """Base64 decrypt with wrong password should return None."""
        original = b"secret data"
        encrypted = self.vault.encrypt_to_base64(original)
        wrong_vault = FileVault("another-password-5678")
        result = wrong_vault.decrypt_from_base64(encrypted)
        self.assertIsNone(result)

    def test_get_summary_empty(self):
        """Empty history should return a 'no operations' status."""
        summary = self.vault.get_summary()
        self.assertIn("No operations", summary["status"])

    def test_get_summary_after_operations(self):
        """Summary after operations should have stats."""
        self.vault.encrypt_file(self.test_file)
        summary = self.vault.get_summary()
        self.assertEqual(summary["total_operations"], 1)
        self.assertEqual(summary["successful"], 1)

    def test_vault_operation_dataclass(self):
        """VaultOperation should store all fields correctly."""
        op = VaultOperation(
            file_path="/test.txt", operation="encrypt",
            success=True, size_bytes=100, duration_ms=50.0
        )
        self.assertEqual(op.file_path, "/test.txt")
        self.assertEqual(op.operation, "encrypt")
        self.assertTrue(op.success)
        self.assertEqual(op.size_bytes, 100)
        self.assertEqual(op.duration_ms, 50.0)
        self.assertIsNone(op.error)

    def test_encrypt_empty_file(self):
        """Encrypting an empty file should succeed."""
        empty_file = os.path.join(self.test_dir, "empty.txt")
        with open(empty_file, 'w') as f:
            f.write("")
        result = self.vault.encrypt_file(empty_file)
        self.assertTrue(result.success)

    def test_decrypt_corrupted_file(self):
        """Decrypting a corrupted vault file should fail."""
        corrupted = os.path.join(self.test_dir, "corrupted.vault")
        with open(corrupted, 'wb') as f:
            f.write(b"not a real vault file at all")
        result = self.vault.decrypt_file(corrupted)
        self.assertFalse(result.success)

    def test_encrypt_binary_file(self):
        """Encrypting/decrypting a binary file should work."""
        binary_file = os.path.join(self.test_dir, "binary.bin")
        with open(binary_file, 'wb') as f:
            f.write(bytes(range(256)))
        result = self.vault.encrypt_file(binary_file)
        self.assertTrue(result.success)

        os.remove(binary_file)
        self.vault.decrypt_file(binary_file + ".vault")
        with open(binary_file, 'rb') as f:
            restored = f.read()
        self.assertEqual(list(restored), list(range(256)))


if __name__ == '__main__':
    unittest.main()