"""
DBSentinel: A lightweight SQLite database integrity monitor.
============================================================
Tracks data integrity using cryptographic hashing, detects INSERT,
UPDATE, and DELETE operations across database tables, and provides
structured integrity reports with schema monitoring.

Grok Build Standards:
- Cryptographic Security: SHA-256 hashing for data integrity verification
- OOP: Clean separation with DBSentinel, ChangeRecord, IntegrityReport
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import sqlite3
import logging
import hashlib
import json
import time
import os
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DBSentinel")


@dataclass
class ChangeRecord:
    """Records a single change detected in the database."""
    table_name: str
    operation: str  # INSERT, UPDATE, DELETE
    row_id: Any
    data_hash: str
    timestamp: float
    previous_hash: str = ""


@dataclass
class IntegrityReport:
    """Aggregated integrity report for a database."""
    db_path: str
    total_tables: int
    total_rows: int
    changes_detected: int
    changes: List[Dict[str, Any]]
    integrity_score: float
    report_time: str
    table_health: Dict[str, Dict[str, Any]]


@dataclass
class TableSchema:
    """Schema information for a database table."""
    name: str
    columns: List[Dict[str, str]]
    row_count: int
    primary_key: Optional[str]
    has_auto_increment: bool
    create_statement: str


class DBSentinel:
    """
    DBSentinel: A lightweight SQLite database integrity monitor.

    Tracks data integrity using cryptographic hashing, detects INSERT,
    UPDATE, and DELETE operations, and provides detailed integrity
    reports with schema monitoring.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.state_hashes: Dict[str, Any] = {}
        self.change_history: List[ChangeRecord] = []
        self.schema_cache: Dict[str, TableSchema] = {}

        if not os.path.exists(db_path):
            logger.warning(f"Database does not exist: {db_path}")
        else:
            self._cache_schema()

    def _cache_schema(self):
        """Cache the schema information for all tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get all tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                tables = [row[0] for row in cursor.fetchall()]

                for table_name in tables:
                    # Get column info
                    cursor.execute(f"PRAGMA table_info(\"{table_name}\")")
                    columns = []
                    primary_key = None
                    has_auto_increment = False
                    for col in cursor.fetchall():
                        col_info = {
                            "name": col[1],
                            "type": col[2],
                            "nullable": not col[3],
                            "default": col[4]
                        }
                        columns.append(col_info)
                        if col[5] == 1:  # pk
                            primary_key = col[1]
                        if col[5] == 1 and col[2].upper() == "INTEGER":
                            has_auto_increment = True

                    # Get row count
                    cursor.execute(f"SELECT COUNT(*) FROM \"{table_name}\"")
                    row_count = cursor.fetchone()[0]

                    # Get CREATE statement
                    cursor.execute(
                        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                        (table_name,)
                    )
                    create_stmt = cursor.fetchone()
                    create_statement = create_stmt[0] if create_stmt else ""

                    self.schema_cache[table_name] = TableSchema(
                        name=table_name,
                        columns=columns,
                        row_count=row_count,
                        primary_key=primary_key,
                        has_auto_increment=has_auto_increment,
                        create_statement=create_statement
                    )

        except sqlite3.Error as e:
            logger.error(f"Failed to cache schema: {e}")

    def _calculate_hash(self, data: Any) -> str:
        """Calculates a SHA-256 hash of the given data."""
        serialized = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(serialized).hexdigest()

    def get_tables(self) -> List[str]:
        """Returns a list of all user tables in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "ORDER BY name"
                )
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Failed to fetch tables: {e}")
            return []

    def get_table_schema(self, table_name: str) -> Optional[TableSchema]:
        """Returns schema information for a specific table."""
        if table_name in self.schema_cache:
            return self.schema_cache[table_name]
        return None

    def get_all_schemas(self) -> Dict[str, TableSchema]:
        """Returns schema information for all tables."""
        return dict(self.schema_cache)

    def compute_table_hash(self, table_name: str) -> Dict[str, str]:
        """
        Computes SHA-256 hashes for each row in a table.

        Args:
            table_name: The name of the table to hash

        Returns:
            Dictionary mapping row_id -> hash for each row
        """
        row_hashes: Dict[str, str] = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get primary key column
                schema = self.schema_cache.get(table_name)
                pk_column = schema.primary_key if schema else "rowid"

                # Use rowid as fallback if no explicit PK
                query = f"SELECT \"{pk_column}\", * FROM \"{table_name}\""

                cursor.execute(query)
                columns = [desc[0] for desc in cursor.description]
                pk_index = 0  # First column is the PK

                for row in cursor.fetchall():
                    row_id = str(row[pk_index])
                    row_data = dict(zip(columns, row))
                    row_hashes[row_id] = self._calculate_hash(row_data)

            return row_hashes
        except sqlite3.Error as e:
            logger.error(f"Failed to hash table {table_name}: {e}")
            return row_hashes

    def detect_changes(self) -> List[ChangeRecord]:
        """
        Compares current state with previous snapshot and detects changes.

        Detects INSERT, UPDATE, and DELETE operations by comparing
        row-level SHA-256 hashes between the current and previous state.

        Returns:
            List of ChangeRecord objects describing detected changes
        """
        if not os.path.exists(self.db_path):
            logger.error(f"Database not found: {self.db_path}")
            return []

        changes: List[ChangeRecord] = []
        tables = self.get_tables()

        for table_name in tables:
            current_snapshot = self.compute_table_hash(table_name)
            previous_snapshot_key = f"table_{table_name}"
            previous_snapshot = self.state_hashes.get(previous_snapshot_key, {})

            if not previous_snapshot:
                # First scan — no changes to report, just store state
                self.state_hashes[previous_snapshot_key] = current_snapshot
                continue

            # Detect New Rows (INSERT)
            for row_id in current_snapshot:
                if row_id not in previous_snapshot:
                    changes.append(ChangeRecord(
                        table_name, "INSERT", row_id,
                        current_snapshot[row_id], time.time()
                    ))

            # Detect Modified Rows (UPDATE)
            for row_id in current_snapshot:
                if (row_id in previous_snapshot and
                        current_snapshot[row_id] != previous_snapshot[row_id]):
                    changes.append(ChangeRecord(
                        table_name, "UPDATE", row_id,
                        current_snapshot[row_id], time.time(),
                        previous_hash=previous_snapshot[row_id]
                    ))

            # Detect Deleted Rows (DELETE)
            for row_id in previous_snapshot:
                if row_id not in current_snapshot:
                    changes.append(ChangeRecord(
                        table_name, "DELETE", row_id,
                        previous_snapshot[row_id], time.time()
                    ))

            # Update state
            self.state_hashes[previous_snapshot_key] = current_snapshot

        self.change_history.extend(changes)
        if changes:
            logger.info(f"Detected {len(changes)} change(s) across {len(tables)} table(s)")
            for change in changes:
                logger.debug(f"  {change.operation} on {change.table_name} (id={change.row_id})")

        return changes

    def get_integrity_report(self) -> IntegrityReport:
        """
        Generates a comprehensive integrity report.

        Returns:
            IntegrityReport with table health, change history, and scoring
        """
        total_tables = len(self.schema_cache)
        total_rows = sum(s.row_count for s in self.schema_cache.values())
        total_changes = len(self.change_history)

        # Calculate table health
        table_health = {}
        for table_name, schema in self.schema_cache.items():
            table_changes = sum(
                1 for c in self.change_history if c.table_name == table_name
            )
            table_health[table_name] = {
                "row_count": schema.row_count,
                "columns": len(schema.columns),
                "primary_key": schema.primary_key,
                "changes_detected": table_changes
            }

        # Integrity score: 100 minus penalty for changes
        integrity_score = max(0, 100 - (total_changes * 2))

        return IntegrityReport(
            db_path=self.db_path,
            total_tables=total_tables,
            total_rows=total_rows,
            changes_detected=total_changes,
            changes=[asdict(c) for c in self.change_history[-50:]],  # Last 50
            integrity_score=round(integrity_score, 1),
            report_time=datetime.now(timezone.utc).isoformat(),
            table_health=table_health
        )

    def save_report(self, filename: str = "db_integrity_report.json"):
        """Saves the integrity report to a JSON file."""
        try:
            report = asdict(self.get_integrity_report())
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Integrity report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def get_summary(self) -> Dict[str, Any]:
        """Returns a summary of monitoring activity."""
        return {
            "db_path": self.db_path,
            "tables_monitored": len(self.schema_cache),
            "total_rows": sum(s.row_count for s in self.schema_cache.values()),
            "total_changes_detected": len(self.change_history),
            "last_changes": [
                asdict(c) for c in self.change_history[-5:]
            ] if self.change_history else []
        }


if __name__ == "__main__":
    # Example usage with a temporary DB
    test_db = "sentinel_test.db"

    # Create test database
    with sqlite3.connect(test_db) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
        )
        conn.execute(
            "INSERT INTO users (name, email) VALUES ('Carlos', 'carlos@example.com')"
        )
        conn.execute(
            "INSERT INTO users (name, email) VALUES ('Ana', 'ana@example.com')"
        )

    monitor = DBSentinel(test_db)
    print("Initial scan (no changes expected)...")
    changes = monitor.detect_changes()
    print(f"  Changes: {len(changes)}")

    print("\nModifying data...")
    with sqlite3.connect(test_db) as conn:
        conn.execute("UPDATE users SET name = 'Mike' WHERE id = 1")
        conn.execute("INSERT INTO users (name, email) VALUES ('Pedro', 'pedro@example.com')")

    changes = monitor.detect_changes()
    print(f"  Changes detected: {len(changes)}")
    for change in changes:
        print(f"  {change.operation} on table {change.table_name} (Row ID: {change.row_id})")

    # Show integrity report
    print("\nIntegrity Report:")
    report = monitor.get_integrity_report()
    print(f"  Tables: {report.total_tables}")
    print(f"  Total rows: {report.total_rows}")
    print(f"  Changes detected: {report.changes_detected}")
    print(f"  Integrity score: {report.integrity_score}/100")

    # Cleanup
    monitor.save_report()
    os.remove(test_db)