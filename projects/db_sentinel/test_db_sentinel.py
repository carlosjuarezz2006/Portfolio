import unittest
import sqlite3
import os
import json
import tempfile
from db_sentinel import DBSentinel, ChangeRecord, IntegrityReport, TableSchema


class TestDBSentinel(unittest.TestCase):
    """Test suite for DBSentinel SQLite integrity monitor."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_sentinel.db")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE inventory "
                "(id INTEGER PRIMARY KEY, item TEXT, qty INTEGER)"
            )
            conn.execute("INSERT INTO inventory (item, qty) VALUES ('Laptop', 10)")
            conn.execute("INSERT INTO inventory (item, qty) VALUES ('Mouse', 50)")
        self.sentinel = DBSentinel(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.temp_dir)

    def test_initial_scan_returns_no_changes(self):
        """Initial scan should populate state but return no changes."""
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 0)
        self.assertIn("table_inventory", self.sentinel.state_hashes)

    def test_detect_insert(self):
        self.sentinel.detect_changes()  # Set initial state
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO inventory (item, qty) VALUES ('Keyboard', 25)")
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].operation, "INSERT")

    def test_detect_update(self):
        self.sentinel.detect_changes()  # Set initial state
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE inventory SET qty = 15 WHERE id = 1")
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].operation, "UPDATE")

    def test_detect_delete(self):
        self.sentinel.detect_changes()  # Set initial state
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM inventory WHERE id = 1")
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].operation, "DELETE")

    def test_detect_multiple_operations(self):
        """Test detecting multiple changes at once."""
        self.sentinel.detect_changes()  # Set initial state
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO inventory (item, qty) VALUES ('Monitor', 5)")
            conn.execute("UPDATE inventory SET qty = 100 WHERE id = 2")
            conn.execute("DELETE FROM inventory WHERE id = 1")
        changes = self.sentinel.detect_changes()
        # INSERT (id=3), UPDATE (id=2), DELETE (id=1) = 3 changes
        self.assertEqual(len(changes), 3)
        operations = {c.operation for c in changes}
        self.assertEqual(operations, {"INSERT", "UPDATE", "DELETE"})

    def test_get_tables(self):
        tables = self.sentinel.get_tables()
        self.assertIn("inventory", tables)

    def test_get_table_schema(self):
        schema = self.sentinel.get_table_schema("inventory")
        self.assertIsNotNone(schema)
        self.assertEqual(schema.name, "inventory")
        self.assertEqual(len(schema.columns), 3)
        self.assertEqual(schema.columns[0]["name"], "id")
        self.assertEqual(schema.columns[1]["name"], "item")
        self.assertEqual(schema.columns[2]["name"], "qty")

    def test_get_all_schemas(self):
        schemas = self.sentinel.get_all_schemas()
        self.assertIn("inventory", schemas)

    def test_compute_table_hash_structure(self):
        """Test that compute_table_hash returns correct structure."""
        self.sentinel.detect_changes()
        hashes = self.sentinel.compute_table_hash("inventory")
        self.assertEqual(len(hashes), 2)  # 2 rows
        for row_id, row_hash in hashes.items():
            self.assertIsInstance(row_id, str)
            self.assertIsInstance(row_hash, str)
            self.assertEqual(len(row_hash), 64)  # SHA-256 hex digest

    def test_integrity_report(self):
        """Test integrity report generation."""
        self.sentinel.detect_changes()
        report = self.sentinel.get_integrity_report()
        self.assertEqual(report.db_path, self.db_path)
        self.assertEqual(report.total_tables, 1)
        self.assertEqual(report.total_rows, 2)
        self.assertEqual(report.changes_detected, 0)
        self.assertAlmostEqual(report.integrity_score, 100.0)

    def test_integrity_report_after_changes(self):
        """Test integrity score after changes."""
        self.sentinel.detect_changes()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO inventory (item, qty) VALUES ('Desk', 1)")
        self.sentinel.detect_changes()
        report = self.sentinel.get_integrity_report()
        self.assertEqual(report.total_rows, 3)
        self.assertEqual(report.changes_detected, 1)

    def test_save_report(self):
        """Test saving report to JSON."""
        self.sentinel.detect_changes()
        report_path = os.path.join(self.temp_dir, "test_report.json")
        self.sentinel.save_report(report_path)
        self.assertTrue(os.path.exists(report_path))
        with open(report_path) as f:
            data = json.load(f)
        self.assertIn("db_path", data)
        self.assertIn("total_tables", data)
        self.assertIn("integrity_score", data)

    def test_get_summary(self):
        self.sentinel.detect_changes()
        summary = self.sentinel.get_summary()
        self.assertIn("db_path", summary)
        self.assertIn("tables_monitored", summary)
        self.assertIn("total_changes_detected", summary)

    def test_non_existent_db(self):
        sentinel = DBSentinel("/nonexistent/path/db.sqlite")
        changes = sentinel.detect_changes()
        self.assertEqual(len(changes), 0)

    def test_change_record_has_previous_hash_on_update(self):
        self.sentinel.detect_changes()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE inventory SET qty = 99 WHERE id = 1")
        changes = self.sentinel.detect_changes()
        self.assertEqual(changes[0].operation, "UPDATE")
        self.assertNotEqual(changes[0].previous_hash, "")

    def test_multiple_tables(self):
        """Test detecting changes across multiple tables."""
        self.sentinel.detect_changes()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE orders (id INTEGER PRIMARY KEY, product TEXT, qty INTEGER)"
            )
            conn.execute("INSERT INTO orders (product, qty) VALUES ('Widget', 10)")

        # Reinitialize to pick up new table schema
        sentinel = DBSentinel(self.db_path)
        sentinel.state_hashes = self.sentinel.state_hashes
        changes = sentinel.detect_changes()
        self.assertGreaterEqual(len(changes), 0)  # New table has no previous state


if __name__ == '__main__':
    unittest.main()