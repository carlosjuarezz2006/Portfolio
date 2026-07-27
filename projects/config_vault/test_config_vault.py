"""
Unit tests for ConfigVault - Secure Configuration Management.
"""

import unittest
import os
import json
import tempfile
import shutil
import tempfile
from config_vault import (
    ConfigVault, ConfigEntry, Profile,
    ConfigVaultError, ProfileNotFoundError, ValidationError,
    HAS_CRYPTO
)


class TestConfigVaultCore(unittest.TestCase):
    """Test suite for ConfigVault core functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.temp_dir, "config_vault.json")
        self.vault = ConfigVault(storage_path=self.storage_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_profile(self):
        """Test creating a new profile."""
        profile = self.vault.create_profile("production", "Production environment")
        self.assertEqual(profile.name, "production")
        self.assertEqual(profile.description, "Production environment")
        self.assertIn("production", self.vault.profiles)

    def test_create_duplicate_profile(self):
        """Test creating a duplicate profile raises error."""
        self.vault.create_profile("production")
        with self.assertRaises(ConfigVaultError):
            self.vault.create_profile("production")

    def test_delete_profile(self):
        """Test deleting a profile."""
        self.vault.create_profile("staging")
        self.vault.delete_profile("staging")
        self.assertNotIn("staging", self.vault.profiles)

    def test_delete_nonexistent_profile(self):
        """Test deleting a non-existent profile."""
        with self.assertRaises(ProfileNotFoundError):
            self.vault.delete_profile("nonexistent")

    def test_get_profile(self):
        """Test retrieving a profile."""
        self.vault.create_profile("dev", "Development")
        profile = self.vault.get_profile("dev")
        self.assertEqual(profile.name, "dev")
        self.assertEqual(profile.description, "Development")

    def test_get_nonexistent_profile(self):
        """Test retrieving a non-existent profile."""
        with self.assertRaises(ProfileNotFoundError):
            self.vault.get_profile("ghost")

    def test_list_profiles_empty(self):
        """Test listing profiles when none exist."""
        self.assertEqual(self.vault.list_profiles(), [])

    def test_list_profiles(self):
        """Test listing multiple profiles."""
        self.vault.create_profile("dev")
        self.vault.create_profile("prod")
        self.assertEqual(sorted(self.vault.list_profiles()), ["dev", "prod"])

    def test_set_entry(self):
        """Test setting a configuration entry."""
        self.vault.create_profile("production")
        entry = self.vault.set_entry("production", "DB_HOST", "localhost",
                                     description="Database host", required=True)
        self.assertEqual(entry.key, "DB_HOST")
        self.assertEqual(entry.value, "localhost")
        self.assertTrue(entry.required)
        self.assertFalse(entry.is_secret)

    def test_set_entry_auto_creates_profile(self):
        """Test that set_entry fails if profile doesn't exist."""
        with self.assertRaises(ProfileNotFoundError):
            self.vault.set_entry("nonexistent", "KEY", "val")

    def test_get_entry(self):
        """Test retrieving an entry."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "API_URL", "http://localhost:8000")
        entry = self.vault.get_entry("dev", "API_URL")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.value, "http://localhost:8000")

    def test_get_entry_not_found(self):
        """Test retrieving a non-existent entry."""
        self.vault.create_profile("dev")
        entry = self.vault.get_entry("dev", "NONEXISTENT")
        self.assertIsNone(entry)

    def test_get_value(self):
        """Test retrieving a raw value."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "PORT", "8080")
        self.assertEqual(self.vault.get_value("dev", "PORT"), "8080")

    def test_get_value_default(self):
        """Test get_value with default."""
        self.vault.create_profile("dev")
        self.assertEqual(self.vault.get_value("dev", "MISSING", "default_val"), "default_val")

    def test_delete_entry(self):
        """Test deleting an entry."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "TEMP_KEY", "temp")
        self.assertTrue(self.vault.delete_entry("dev", "TEMP_KEY"))
        self.assertIsNone(self.vault.get_entry("dev", "TEMP_KEY"))

    def test_delete_nonexistent_entry(self):
        """Test deleting a non-existent entry."""
        self.vault.create_profile("dev")
        self.assertFalse(self.vault.delete_entry("dev", "GHOST"))

    def test_validate_value_valid(self):
        """Test value validation with a valid value."""
        is_valid, msg = self.vault.validate_value("URL", "https://example.com", "url")
        self.assertTrue(is_valid)
        self.assertEqual(msg, "")

    def test_validate_value_invalid(self):
        """Test value validation with an invalid value."""
        is_valid, msg = self.vault.validate_value("PORT", "not_a_port", "port")
        self.assertFalse(is_valid)
        self.assertIn("failed port validation", msg)

    def test_validate_value_unknown_validator(self):
        """Test value validation with an unknown validator name."""
        is_valid, msg = self.vault.validate_value("X", "y", "unknown_validator")
        self.assertFalse(is_valid)
        self.assertIn("Unknown validator", msg)

    def test_validation_error_on_set(self):
        """Test that setting a value with invalid validation raises."""
        self.vault.create_profile("dev")
        with self.assertRaises(ValidationError):
            self.vault.set_entry("dev", "PORT", "not_a_number", validator="port")

    def test_validate_profile_no_errors(self):
        """Test validating a profile with no issues."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "HOST", "localhost", required=True)
        self.vault.set_entry("dev", "PORT", "8080", validator="port")
        errors = self.vault.validate_profile("dev")
        self.assertEqual(errors, [])

    def test_validate_profile_missing_required(self):
        """Test validation detects missing required entry."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "REQUIRED_KEY", "", required=True)
        errors = self.vault.validate_profile("dev")
        self.assertGreater(len(errors), 0)
        self.assertIn("Required entry", errors[0])

    def test_validate_profile_invalid_value(self):
        """Test validation detects invalid value."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "URL", "not-a-url", validator="url")
        errors = self.vault.validate_profile("dev")
        self.assertGreater(len(errors), 0)

    def test_export_env(self):
        """Test exporting a profile to .env format."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "HOST", "example.com", description="Server host")
        self.vault.set_entry("dev", "PORT", "443")

        export_path = os.path.join(self.temp_dir, ".env")
        count = self.vault.export_env("dev", export_path)
        self.assertEqual(count, 2)

        with open(export_path) as f:
            content = f.read()
        self.assertIn("HOST=example.com", content)
        self.assertIn("PORT=443", content)
        self.assertIn("Server host", content)

    def test_export_env_with_secrets(self):
        """Test exporting secrets (should be hidden by default)."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "API_KEY", "supersecret", is_secret=True)
        export_path = os.path.join(self.temp_dir, ".env")
        count = self.vault.export_env("dev", export_path)
        self.assertEqual(count, 1)
        with open(export_path) as f:
            content = f.read()
        self.assertIn("SECRET", content)
        self.assertNotIn("supersecret", content)

    def test_import_env(self):
        """Test importing from a .env file."""
        env_path = os.path.join(self.temp_dir, "import.env")
        with open(env_path, 'w') as f:
            f.write("# Test config\n")
            f.write("DB_HOST=localhost\n")
            f.write('DB_NAME="my_database"\n')
            f.write("API_KEY=sk-secret-key\n")

        count = self.vault.import_env("production", env_path)
        self.assertEqual(count, 3)
        self.assertIn("production", self.vault.profiles)
        self.assertEqual(self.vault.get_value("production", "DB_HOST"), "localhost")
        # API_KEY should be marked as secret
        entry = self.vault.get_entry("production", "API_KEY")
        self.assertTrue(entry.is_secret)

    def test_render_template(self):
        """Test template rendering with variable substitution."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "DB_HOST", "localhost")
        self.vault.set_entry("dev", "DB_PORT", "5432")

        template_path = os.path.join(self.temp_dir, "template.txt")
        with open(template_path, 'w') as f:
            f.write("host={{DB_HOST}}\nport={{DB_PORT}}")

        output_path = os.path.join(self.temp_dir, "output.txt")
        count = self.vault.render_template(template_path, "dev", output_path)
        self.assertEqual(count, 2)

        with open(output_path) as f:
            content = f.read()
        self.assertIn("host=localhost", content)
        self.assertIn("port=5432", content)

    def test_generate_secret(self):
        """Test cryptographically secure secret generation."""
        secret = self.vault.generate_secret(16)
        self.assertEqual(len(secret), 16)
        self.assertTrue(all(c.isalnum() for c in secret))

        secret_with_punct = self.vault.generate_secret(32, use_punctuation=True)
        self.assertEqual(len(secret_with_punct), 32)
        has_punct = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in secret_with_punct)
        self.assertTrue(has_punct)

    def test_summary_empty(self):
        """Test summary with no profiles."""
        summary = self.vault.get_summary()
        self.assertEqual(summary["total_profiles"], 0)
        self.assertEqual(summary["total_entries"], 0)

    def test_summary_with_data(self):
        """Test summary with profiles and entries."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "KEY", "val", is_secret=True)
        self.vault.create_profile("prod")
        self.vault.set_entry("prod", "KEY2", "val2")

        summary = self.vault.get_summary()
        self.assertEqual(summary["total_profiles"], 2)
        self.assertEqual(summary["total_entries"], 2)
        self.assertEqual(summary["secret_entries"], 1)

    def test_persistence(self):
        """Test that data persists across ConfigVault instances."""
        self.vault.create_profile("dev")
        self.vault.set_entry("dev", "PERSIST", "test_value")

        # Create a new instance pointing to the same storage
        vault2 = ConfigVault(storage_path=self.storage_path)
        self.assertIn("dev", vault2.profiles)
        self.assertEqual(vault2.get_value("dev", "PERSIST"), "test_value")

    def test_secret_encryption(self):
        """Test that secret values are encrypted at rest."""
        if not HAS_CRYPTO:
            self.skipTest("Cryptography library not available")

        vault = ConfigVault(storage_path=self.storage_path, master_key="test-master-key")
        vault.create_profile("dev")
        vault.set_entry("dev", "API_KEY", "my-secret-api-key", is_secret=True)

        # Read raw JSON to verify encryption
        with open(self.storage_path) as f:
            data = json.load(f)
        stored_value = data["profiles"]["dev"]["entries"]["API_KEY"]["value"]
        self.assertNotEqual(stored_value, "my-secret-api-key")
        self.assertTrue(stored_value.startswith("gAAAAA"))  # Fernet prefix

        # Verify decryption works
        entry = vault.get_entry("dev", "API_KEY")
        self.assertEqual(entry.value, "my-secret-api-key")


if __name__ == '__main__':
    unittest.main()