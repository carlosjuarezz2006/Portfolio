# DBSentinel

A lightweight SQLite database integrity monitor that tracks data changes using cryptographic hashing, detects INSERT/UPDATE/DELETE operations, and provides structured integrity reports with schema monitoring.

## Features
- **Cryptographic Hashing**: SHA-256 row-level hashing for data integrity verification.
- **Change Detection**: Detects INSERT, UPDATE, and DELETE operations across all tables.
- **Schema Monitoring**: Caches table schemas (columns, types, primary keys, auto-increment).
- **Integrity Scoring**: Calculates a 0-100 integrity score based on change history.
- **Structured Reports**: `IntegrityReport` dataclass with JSON export for compliance.
- **Change History**: Tracks all changes with previous hash comparison for UPDATE operations.
- **Multi-Table Support**: Monitors all user tables in the database automatically.

## Grok Build Standards
- **Cryptographic Security**: SHA-256 hashing (standard library `hashlib`) for data integrity verification.
- **OOP Architecture**: Clean separation with `DBSentinel`, `ChangeRecord`, `IntegrityReport`, and `TableSchema` classes.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 20+ unit tests.

## Usage
```python
from db_sentinel import DBSentinel

monitor = DBSentinel("my_database.db")

# Detect changes since last scan
changes = monitor.detect_changes()
for change in changes:
    print(f"{change.operation} on {change.table_name} (id={change.row_id})")

# Get integrity report
report = monitor.get_integrity_report()
print(f"Integrity score: {report.integrity_score}/100")

# Get schema information
schema = monitor.get_table_schema("users")
print(f"Table '{schema.name}' has {len(schema.columns)} columns")

# Save report
monitor.save_report("db_report.json")
```

## CLI Usage
```bash
python db_sentinel.py
```