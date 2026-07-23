# DBSentinel

DBSentinel is a lightweight database integrity monitor for SQLite. It uses cryptographic hashing to detect changes (INSERT, UPDATE, DELETE) in your data without requiring complex database triggers.

## Features
- **Integrity Tracking**: Uses SHA-256 to hash row data and detect tampering or unintended updates.
- **Auto-Discovery**: Automatically scans all tables in a provided SQLite database file.
- **Delta Detection**: Identifies specifically which operation (INSERT/UPDATE/DELETE) occurred and on which row.
- **OOP Architecture**: Built with clean classes and Python dataclasses for structured change records.

## Grok Build Standards
- **Cryptographic Security**: Employs `hashlib.sha256` for robust data fingerprinting.
- **Professional Documentation**: Full type hinting and descriptive docstrings.
- **Reliability**: Graceful handling of SQLite operational errors.

## Usage
```python
from db_sentinel import DBSentinel

sentinel = DBSentinel("my_app.db")
# Run periodically or as a daemon
changes = sentinel.detect_changes()
for change in changes:
    print(f"[{change.operation}] Table: {change.table_name}, Row ID: {change.row_id}")
```
