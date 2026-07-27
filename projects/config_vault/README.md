# ConfigVault

A secure configuration management tool for IT professionals. Manages environment variables and configuration files with encryption, template rendering, validation, and multi-profile support.

## Features
- **Multi-Profile Management**: Create separate profiles for development, staging, production, or any environment.
- **Fernet-Encrypted Secrets**: Sensitive values (API keys, passwords, tokens) are encrypted at rest using AES-128-CBC with HMAC authentication.
- **Template Rendering**: Render configuration files from templates using `{{KEY}}` variable substitution syntax.
- **Validation Rules**: Built-in validators for URLs, emails, ports, IP addresses, hostnames, and more.
- **.env Import/Export**: Seamless migration between ConfigVault and standard .env files.
- **Secure Secret Generation**: Cryptographically secure random value generator (secrets module).
- **Atomic Writes**: All storage operations use atomic file writes to prevent corruption.
- **JSON Persistence**: All profiles stored in a single JSON file with automatic loading/saving.

## Grok Build Standards
- **Cryptographic Security**: Uses `cryptography.fernet` (AES-128-CBC with HMAC) for secret encryption, PBKDF2-HMAC-SHA256 for key derivation with 600,000 iterations.
- **OOP Architecture**: Clean separation with `ConfigVault`, `Profile`, `ConfigEntry` dataclasses, and custom exception hierarchy.
- **Professional Documentation**: Full type hints, comprehensive docstrings, structured logging, and 25+ unit tests.

## Usage
```python
from config_vault import ConfigVault

vault = ConfigVault()

# Create a profile
vault.create_profile("production", "Production environment settings")

# Set configuration entries
vault.set_entry("production", "DB_HOST", "db.example.com", required=True)
vault.set_entry("production", "DB_PORT", "5432", validator="port")
vault.set_entry("production", "API_KEY", "sk-abc123", is_secret=True)

# Get values
host = vault.get_value("production", "DB_HOST")
api_key = vault.get_value("production", "API_KEY")

# Validate profile
errors = vault.validate_profile("production")
if errors:
    print(f"Validation errors: {errors}")

# Export to .env
vault.export_env("production", ".env.production")

# Import from .env
vault.import_env("staging", ".env.staging")

# Render a template
vault.render_template("config.template", "production", "config.yaml")

# Generate a secure secret
token = vault.generate_secret(32, use_punctuation=True)
```

## CLI Usage
```bash
python config_vault.py profiles                          # List profiles
python config_vault.py create myprofile "My config"      # Create a profile
python config_vault.py set myprofile DB_HOST localhost   # Set an entry
python config_vault.py set myprofile API_KEY sk-abc --secret  # Set a secret
python config_vault.py get myprofile DB_HOST             # Get a value
python config_vault.py export myprofile .env.prod        # Export to .env
python config_vault.py import myprofile .env.dev         # Import from .env
python config_vault.py render template.txt myprofile out.txt  # Render template
python config_vault.py summary                           # Show summary
```

## Validation Rules
| Validator | Pattern | Example |
|-----------|---------|---------|
| `url` | `^https?://...` | `https://example.com` |
| `email` | RFC 5322-like | `user@example.com` |
| `port` | `^\\d{1,5}$` | `8080` |
| `hostname` | RFC 952-like | `my-server-1` |
| `ipv4` | `^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$` | `192.168.1.1` |
| `integer` | `^-?\\d+$` | `42` |
| `float` | `^-?\\d+(\\.\\d+)?$` | `3.14` |
| `boolean` | `true/false/yes/no/1/0` | `true` |
| `alphanumeric` | `^[a-zA-Z0-9_]+$` | `my_var_1` |