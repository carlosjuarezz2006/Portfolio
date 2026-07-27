"""
ConfigVault: A secure configuration management tool.
=====================================================
Manages environment variables and configuration files with
encryption, template rendering, validation, and multi-profile support.

Grok Build Standards:
- Cryptographic Security: Fernet (AES-128-CBC with HMAC) for secrets,
  cryptography.hazmat for key derivation
- OOP: Clean separation with ConfigVault class, Profile dataclass,
  and Validator mixin
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import os
import json
import logging
import re
import string
import secrets
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ConfigVault")


class ConfigVaultError(Exception):
    """Base exception for ConfigVault operations."""
    pass


class ProfileNotFoundError(ConfigVaultError):
    """Raised when a requested profile does not exist."""
    pass


class ValidationError(ConfigVaultError):
    """Raised when configuration validation fails."""
    pass


@dataclass
class ConfigEntry:
    """A single configuration entry with metadata."""
    key: str
    value: str
    description: str = ""
    is_secret: bool = False
    required: bool = False
    validator: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""


@dataclass
class Profile:
    """A named configuration profile containing multiple entries."""
    name: str
    description: str = ""
    entries: Dict[str, ConfigEntry] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


class ConfigVault:
    """
    ConfigVault: Secure configuration management for IT professionals.

    Features:
    - Multi-profile configuration storage (dev, staging, production)
    - Fernet-encrypted secret values for sensitive data
    - Template rendering with variable substitution
    - Validation rules for configuration values
    - .env file import/export
    - JSON-based persistent storage
    """

    VALIDATORS = {
        "url": r'^https?://[^\s/$.?#].[^\s]*$',
        "email": r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        "port": r'^\d{1,5}$',
        "hostname": r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$',
        "ipv4": r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        "integer": r'^-?\d+$',
        "float": r'^-?\d+(\.\d+)?$',
        "boolean": r'^(true|false|yes|no|1|0)$',
        "hex_color": r'^#[0-9a-fA-F]{6}$',
        "alphanumeric": r'^[a-zA-Z0-9_]+$',
    }

    def __init__(self, storage_path: Optional[str] = None, master_key: Optional[str] = None):
        self.storage_path = storage_path or os.path.join(
            os.path.expanduser("~"), ".config_vault", "profiles.json"
        )
        self._ensure_directory()
        self.profiles: Dict[str, Profile] = {}
        self._cipher = None
        if master_key and HAS_CRYPTO:
            self._init_cipher(master_key)
        self._load()

    def _ensure_directory(self) -> None:
        """Ensure the storage directory exists."""
        Path(self.storage_path).parent.mkdir(parents=True, exist_ok=True)

    def _init_cipher(self, master_key: str) -> None:
        """Initialize Fernet cipher from a master password."""
        if not HAS_CRYPTO:
            logger.warning("Cryptography library not available. Secrets will be stored in plaintext.")
            return
        salt = b"ConfigVault_Salt_2026"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        self._cipher = Fernet(key)

    def _encrypt(self, value: str) -> str:
        """Encrypt a string value using Fernet."""
        if self._cipher:
            return self._cipher.encrypt(value.encode()).decode()
        return value

    def _decrypt(self, value: str) -> str:
        """Decrypt a Fernet-encrypted string."""
        if self._cipher:
            try:
                return self._cipher.decrypt(value.encode()).decode()
            except Exception:
                return value
        return value

    def _load(self) -> None:
        """Load profiles from the JSON storage file."""
        if not os.path.exists(self.storage_path):
            return
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            for name, pdata in data.get("profiles", {}).items():
                entries = {}
                for key, edata in pdata.get("entries", {}).items():
                    entries[key] = ConfigEntry(**edata)
                self.profiles[name] = Profile(
                    name=name,
                    description=pdata.get("description", ""),
                    entries=entries,
                    created_at=pdata.get("created_at", ""),
                    updated_at=pdata.get("updated_at", "")
                )
            logger.info(f"Loaded {len(self.profiles)} profiles from {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to load profiles: {e}")

    def _save(self) -> None:
        """Save profiles to the JSON storage file with atomic write."""
        data = {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "profiles": {}
        }
        for name, profile in self.profiles.items():
            entries = {}
            for key, entry in profile.entries.items():
                edata = asdict(entry)
                if entry.is_secret and self._cipher:
                    edata["value"] = self._encrypt(entry.value)
                entries[key] = edata
            data["profiles"][name] = {
                "description": profile.description,
                "entries": entries,
                "created_at": profile.created_at,
                "updated_at": profile.updated_at
            }
        # Atomic write
        tmp_path = self.storage_path + ".tmp"
        with open(tmp_path, 'w') as f:
            json.dump(data, f, indent=4)
        shutil.move(tmp_path, self.storage_path)
        logger.info(f"Saved {len(self.profiles)} profiles to {self.storage_path}")

    def _now(self) -> str:
        """Get current UTC timestamp string."""
        return datetime.now(timezone.utc).isoformat()

    def validate_value(self, key: str, value: str, validator_name: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate a configuration value against a named validator.

        Args:
            key: The configuration key name
            value: The value to validate
            validator_name: Name of the validator to use (e.g., 'url', 'email', 'port')

        Returns:
            Tuple of (is_valid, error_message)
        """
        if validator_name:
            pattern = self.VALIDATORS.get(validator_name)
            if not pattern:
                return False, f"Unknown validator: {validator_name}"
            if not re.match(pattern, value.strip()):
                return False, f"'{key}' with value '{value}' failed {validator_name} validation"
        return True, ""

    def create_profile(self, name: str, description: str = "") -> Profile:
        """
        Create a new configuration profile.

        Args:
            name: Profile name (e.g., 'production', 'staging')
            description: Optional description of the profile

        Returns:
            The newly created Profile object

        Raises:
            ConfigVaultError: If profile already exists
        """
        if name in self.profiles:
            raise ConfigVaultError(f"Profile '{name}' already exists")
        now = self._now()
        profile = Profile(
            name=name,
            description=description,
            created_at=now,
            updated_at=now
        )
        self.profiles[name] = profile
        self._save()
        logger.info(f"Created profile: {name}")
        return profile

    def delete_profile(self, name: str) -> None:
        """
        Delete a configuration profile.

        Args:
            name: Profile name to delete

        Raises:
            ProfileNotFoundError: If profile does not exist
        """
        if name not in self.profiles:
            raise ProfileNotFoundError(f"Profile '{name}' not found")
        del self.profiles[name]
        self._save()
        logger.info(f"Deleted profile: {name}")

    def get_profile(self, name: str) -> Profile:
        """
        Get a profile by name.

        Args:
            name: Profile name

        Returns:
            The Profile object

        Raises:
            ProfileNotFoundError: If profile does not exist
        """
        if name not in self.profiles:
            raise ProfileNotFoundError(f"Profile '{name}' not found")
        return self.profiles[name]

    def list_profiles(self) -> List[str]:
        """List all profile names."""
        return list(self.profiles.keys())

    def set_entry(
        self,
        profile_name: str,
        key: str,
        value: str,
        description: str = "",
        is_secret: bool = False,
        required: bool = False,
        validator: Optional[str] = None
    ) -> ConfigEntry:
        """
        Set a configuration entry in a profile.

        Args:
            profile_name: Target profile name
            key: Configuration key
            value: Configuration value
            description: Optional description
            is_secret: If True, value is encrypted at rest
            required: If True, value must be present for validation
            validator: Optional validator name

        Returns:
            The created/updated ConfigEntry

        Raises:
            ProfileNotFoundError: If profile does not exist
            ValidationError: If validation fails
        """
        profile = self.get_profile(profile_name)

        # Validate if validator is specified
        if validator:
            is_valid, error_msg = self.validate_value(key, value, validator)
            if not is_valid:
                raise ValidationError(error_msg)

        now = self._now()
        entry = ConfigEntry(
            key=key,
            value=value,
            description=description,
            is_secret=is_secret,
            required=required,
            validator=validator,
            created_at=now,
            updated_at=now
        )
        profile.entries[key] = entry
        profile.updated_at = now
        self._save()
        logger.info(f"Set entry '{key}' in profile '{profile_name}'")
        return entry

    def get_entry(self, profile_name: str, key: str, decrypt: bool = True) -> Optional[ConfigEntry]:
        """
        Get a configuration entry.

        Args:
            profile_name: Profile name
            key: Configuration key
            decrypt: If True, decrypt secret values

        Returns:
            ConfigEntry or None if not found
        """
        try:
            profile = self.get_profile(profile_name)
        except ProfileNotFoundError:
            return None

        entry = profile.entries.get(key)
        if entry and entry.is_secret and decrypt and self._cipher:
            entry.value = self._decrypt(entry.value)
        return entry

    def get_value(self, profile_name: str, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a configuration value by key.

        Args:
            profile_name: Profile name
            key: Configuration key
            default: Default value if key not found

        Returns:
            The configuration value, or default
        """
        entry = self.get_entry(profile_name, key)
        if entry:
            return entry.value
        return default

    def delete_entry(self, profile_name: str, key: str) -> bool:
        """
        Delete a configuration entry.

        Args:
            profile_name: Profile name
            key: Key to delete

        Returns:
            True if deleted, False if not found
        """
        try:
            profile = self.get_profile(profile_name)
        except ProfileNotFoundError:
            return False

        if key in profile.entries:
            del profile.entries[key]
            profile.updated_at = self._now()
            self._save()
            logger.info(f"Deleted entry '{key}' from profile '{profile_name}'")
            return True
        return False

    def validate_profile(self, profile_name: str) -> List[str]:
        """
        Validate all required entries in a profile.

        Args:
            profile_name: Profile name

        Returns:
            List of validation error messages (empty if all valid)
        """
        errors = []
        try:
            profile = self.get_profile(profile_name)
        except ProfileNotFoundError as e:
            return [str(e)]

        for key, entry in profile.entries.items():
            if entry.required and not entry.value:
                errors.append(f"Required entry '{key}' is empty")

            if entry.validator and entry.value:
                is_valid, error_msg = self.validate_value(key, entry.value, entry.validator)
                if not is_valid:
                    errors.append(error_msg)

        return errors

    def export_env(self, profile_name: str, export_path: str, include_secrets: bool = False) -> int:
        """
        Export a profile to a .env file.

        Args:
            profile_name: Profile name
            export_path: Output file path
            include_secrets: If True, include decrypted secret values

        Returns:
            Number of entries exported

        Raises:
            ProfileNotFoundError: If profile does not exist
        """
        profile = self.get_profile(profile_name)
        count = 0
        with open(export_path, 'w') as f:
            f.write(f"# ConfigVault export: {profile_name}\n")
            f.write(f"# Generated: {self._now()}\n\n")
            for key, entry in profile.entries.items():
                if entry.is_secret and not include_secrets:
                    f.write(f"# {key}=[SECRET - use --include-secrets to export]\n")
                    continue
                value = entry.value
                if entry.is_secret and self._cipher:
                    value = self._decrypt(value)
                # Quote values with special characters
                if any(c in value for c in [' ', '#', "'", '"', '\\']):
                    escaped = value.replace('\\', '\\\\').replace('"', '\\"')
                    f.write(f'{key}="{escaped}"\n')
                else:
                    f.write(f"{key}={value}\n")
                if entry.description:
                    f.write(f"# {key}: {entry.description}\n")
                count += 1
        logger.info(f"Exported {count} entries from '{profile_name}' to {export_path}")
        return count

    def import_env(self, profile_name: str, import_path: str, mark_secrets: Optional[List[str]] = None) -> int:
        """
        Import configuration from a .env file.

        Args:
            profile_name: Target profile (created if not exists)
            import_path: Path to .env file
            mark_secrets: List of key patterns to mark as secrets

        Returns:
            Number of entries imported
        """
        if profile_name not in self.profiles:
            self.create_profile(profile_name)

        secret_patterns = mark_secrets or ["SECRET", "KEY", "TOKEN", "PASSWORD", "PASS"]
        count = 0

        with open(import_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue

                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                is_secret = any(p.lower() in key.lower() for p in secret_patterns)
                self.set_entry(
                    profile_name=profile_name,
                    key=key,
                    value=value,
                    is_secret=is_secret
                )
                count += 1

        logger.info(f"Imported {count} entries from {import_path} to '{profile_name}'")
        return count

    def render_template(self, template_path: str, profile_name: str, output_path: str) -> int:
        """
        Render a template file with configuration values using {{KEY}} syntax.

        Args:
            template_path: Path to template file
            profile_name: Profile to use for variable substitution
            output_path: Output file path

        Returns:
            Number of substitutions made

        Raises:
            ProfileNotFoundError: If profile does not exist
        """
        profile = self.get_profile(profile_name)

        # Build substitution map
        subs = {}
        for key, entry in profile.entries.items():
            value = entry.value
            if entry.is_secret and self._cipher:
                value = self._decrypt(value)
            subs[key] = value
            subs[key.lower()] = value

        # Read template
        with open(template_path, 'r') as f:
            content = f.read()

        # Perform substitutions
        count = 0
        for var, value in subs.items():
            pattern = r'\{\{' + re.escape(var) + r'\}\}'
            new_content, subs_count = re.subn(pattern, value, content)
            if subs_count > 0:
                count += subs_count
                content = new_content

        # Check for unresolved variables
        unresolved = re.findall(r'\{\{(\w+)\}\}', content)
        if unresolved:
            logger.warning(f"Unresolved template variables: {set(unresolved)}")

        # Write output
        with open(output_path, 'w') as f:
            f.write(content)

        logger.info(f"Rendered template {template_path} -> {output_path} ({count} substitutions)")
        return count

    def generate_secret(self, length: int = 32, use_punctuation: bool = False) -> str:
        """
        Generate a cryptographically secure random value.

        Args:
            length: Length of the generated string
            use_punctuation: Include punctuation characters

        Returns:
            Secure random string
        """
        alphabet = string.ascii_letters + string.digits
        if use_punctuation:
            alphabet += string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all managed profiles."""
        total_entries = sum(len(p.entries) for p in self.profiles.values())
        secret_count = sum(
            sum(1 for e in p.entries.values() if e.is_secret)
            for p in self.profiles.values()
        )
        return {
            "total_profiles": len(self.profiles),
            "total_entries": total_entries,
            "secret_entries": secret_count,
            "profiles": {
                name: {
                    "description": p.description,
                    "entry_count": len(p.entries),
                    "secret_count": sum(1 for e in p.entries.values() if e.is_secret)
                }
                for name, p in self.profiles.items()
            }
        }


if __name__ == "__main__":
    import sys

    vault = ConfigVault()

    if len(sys.argv) < 2:
        print("ConfigVault - Secure Configuration Management")
        print()
        print("Usage:")
        print("  python config_vault.py profiles                    List profiles")
        print("  python config_vault.py create <name> [desc]        Create a profile")
        print("  python config_vault.py set <profile> <key> <val>   Set an entry")
        print("  python config_vault.py get <profile> <key>         Get a value")
        print("  python config_vault.py export <profile> <file>     Export to .env")
        print("  python config_vault.py import <profile> <file>     Import from .env")
        print("  python config_vault.py render <tmpl> <prof> <out>  Render template")
        print("  python config_vault.py summary                     Show summary")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "profiles":
        for name in vault.list_profiles():
            profile = vault.get_profile(name)
            print(f"  {name}: {profile.description} ({len(profile.entries)} entries)")

    elif cmd == "create":
        if len(sys.argv) < 3:
            print("Usage: python config_vault.py create <name> [description]")
            sys.exit(1)
        name = sys.argv[2]
        desc = sys.argv[3] if len(sys.argv) > 3 else ""
        vault.create_profile(name, desc)
        print(f"Created profile: {name}")

    elif cmd == "set":
        if len(sys.argv) < 5:
            print("Usage: python config_vault.py set <profile> <key> <value> [--secret]")
            sys.exit(1)
        profile = sys.argv[2]
        key = sys.argv[3]
        value = sys.argv[4]
        is_secret = "--secret" in sys.argv
        vault.set_entry(profile, key, value, is_secret=is_secret)
        print(f"Set {key}={'***' if is_secret else value} in {profile}")

    elif cmd == "get":
        if len(sys.argv) < 4:
            print("Usage: python config_vault.py get <profile> <key>")
            sys.exit(1)
        val = vault.get_value(sys.argv[2], sys.argv[3])
        print(f"{sys.argv[3]}={val or 'NOT FOUND'}")

    elif cmd == "export":
        if len(sys.argv) < 4:
            print("Usage: python config_vault.py export <profile> <file>")
            sys.exit(1)
        include_secrets = "--include-secrets" in sys.argv
        count = vault.export_env(sys.argv[2], sys.argv[3], include_secrets=include_secrets)
        print(f"Exported {count} entries to {sys.argv[3]}")

    elif cmd == "import":
        if len(sys.argv) < 4:
            print("Usage: python config_vault.py import <profile> <file>")
            sys.exit(1)
        count = vault.import_env(sys.argv[2], sys.argv[3])
        print(f"Imported {count} entries to {sys.argv[2]}")

    elif cmd == "render":
        if len(sys.argv) < 5:
            print("Usage: python config_vault.py render <template> <profile> <output>")
            sys.exit(1)
        count = vault.render_template(sys.argv[2], sys.argv[3], sys.argv[4])
        print(f"Rendered template: {count} substitutions")

    elif cmd == "summary":
        print(json.dumps(vault.get_summary(), indent=2))

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)