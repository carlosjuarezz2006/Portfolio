import sqlite3
import logging
import hashlib
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DBSentinel")

@dataclass
class ChangeRecord:
    table_name: str
    operation: str
    row_id: Any
    data_hash: str
    timestamp: float

class DBSentinel:
    """
    DBSentinel: A lightweight SQLite database monitor that tracks data integrity 
    using cryptographic hashing and structured logging.
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.state_hashes: Dict[str, str] = {}

    def _calculate_hash(self, data: Any) -> str:
        """Calculates a SHA-256 hash of the given data."""
        serialized = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(serialized).hexdigest()

    def get_tables(self) -> List[str]:
        """Returns a list of all tables in the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            return []

    def snapshot_table(self, table_name: str) -> Dict[Any, str]:
        """Creates a map of row IDs to their cryptographic hashes."""
        row_hashes = {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(f"SELECT rowid, * FROM {table_name}")
                rows = cursor.fetchall()
                for row in rows:
                    data = dict(row)
                    row_id = data.pop('rowid')
                    row_hashes[row_id] = self._calculate_hash(data)
        except sqlite3.Error as e:
            logger.error(f"Error snapshotting table {table_name}: {e}")
        return row_hashes

    def detect_changes(self) -> List[ChangeRecord]:
        """Detects modifications, additions, or deletions across all tables."""
        changes = []
        current_tables = self.get_tables()
        
        for table in current_tables:
            current_snapshot = self.snapshot_table(table)
            previous_snapshot_key = f"table_{table}"
            previous_snapshot = self.state_hashes.get(previous_snapshot_key, {})

            if not previous_snapshot:
                logger.info(f"First scan for table: {table}. Initializing state.")
                self.state_hashes[previous_snapshot_key] = current_snapshot
                continue

            # Detect Added or Modified
            for row_id, current_hash in current_snapshot.items():
                if row_id not in previous_snapshot:
                    changes.append(ChangeRecord(table, "INSERT", row_id, current_hash, time.time()))
                elif previous_snapshot[row_id] != current_hash:
                    changes.append(ChangeRecord(table, "UPDATE", row_id, current_hash, time.time()))

            # Detect Deleted
            for row_id in previous_snapshot:
                if row_id not in current_snapshot:
                    changes.append(ChangeRecord(table, "DELETE", row_id, previous_snapshot[row_id], time.time()))

            # Update state
            self.state_hashes[previous_snapshot_key] = current_snapshot

        return changes

if __name__ == "__main__":
    # Example usage with a temporary DB
    test_db = "sentinel_test.db"
    with sqlite3.connect(test_db) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
        conn.execute("INSERT INTO users (name, email) VALUES ('Carlos', 'carlos@example.com')")
    
    monitor = DBSentinel(test_db)
    print("Initial scan...")
    monitor.detect_changes()
    
    print("Modifying data...")
    with sqlite3.connect(test_db) as conn:
        conn.execute("UPDATE users SET name = 'Mike' WHERE id = 1")
        conn.execute("INSERT INTO users (name, email) VALUES ('Ana', 'ana@example.com')")
    
    changes = monitor.detect_changes()
    for change in changes:
        print(f"Detected: {change.operation} on table {change.table_name} (Row ID: {change.row_id})")
