import unittest
import sqlite3
import os
from db_sentinel import DBSentinel

class TestDBSentinel(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_sentinel.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("CREATE TABLE inventory (id INTEGER PRIMARY KEY, item TEXT, qty INTEGER)")
            conn.execute("INSERT INTO inventory (item, qty) VALUES ('Laptop', 10)")
        
        self.sentinel = DBSentinel(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_initial_scan(self):
        # Initial scan should populate state but return no changes
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 0)
        self.assertIn("table_inventory", self.sentinel.state_hashes)

    def test_detect_insert(self):
        self.sentinel.detect_changes() # Set initial state
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO inventory (item, qty) VALUES ('Mouse', 50)")
            
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].operation, "INSERT")

    def test_detect_update(self):
        self.sentinel.detect_changes() # Set initial state
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE inventory SET qty = 15 WHERE id = 1")
            
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].operation, "UPDATE")

    def test_detect_delete(self):
        self.sentinel.detect_changes() # Set initial state
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM inventory WHERE id = 1")
            
        changes = self.sentinel.detect_changes()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].operation, "DELETE")

if __name__ == '__main__':
    unittest.main()
