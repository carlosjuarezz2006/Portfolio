"""
Unit tests for HashChecker - File Integrity Verification Tool.
"""

import unittest
import os
import json
import tempfile
import shutil
import hashlib
from pathlib import Path
from hash_checker import (
    HashChecker, FileHash, VerificationReport, SUPPORTED_ALGORITHMS
)


class TestHashCheckerCore(unittest.TestCase):
    """Test suite for HashChecker core functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.checker = HashChecker(algorithm="sha256", workers=2)

        # Create test files
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("Hello, HashChecker!")

        self.test_binary = os.path.join(self.temp_dir, "test.bin")
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00\x01\x02\x03" * 256)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_hash_file_success(self):
        """Hash a single file successfully."""
        result = self.checker.hash_file(self.test_file)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "computed")
        self.assertEqual(result.algorithm, "sha256")
        self.assertGreater(result.file_size_bytes, 0)
        self.assertEqual(len(result.hash_value), 64)  # SHA-256 hex

    def test_hash_file_nonexistent(self):
        """Non-existent file returns None."""
        result = self.checker.hash_file("/nonexistent/file.txt")
        self.assertIsNone(result)

    def test_hash_file_knowledge(self):
        """Verify known hash value."""
        result = self.checker.hash_file(self.test_file)
        expected = hashlib.sha256(b"Hello, HashChecker!").hexdigest()
        self.assertEqual(result.hash_value, expected)

    def test_hash_file_binary(self):
        """Hash a binary file correctly."""
        result = self.checker.hash_file(self.test_binary)
        self.assertIsNotNone(result)
        self.assertEqual(result.file_size_bytes, 1024)

    def test_hash_directory(self):
        """Hash all files in a directory."""
        results = self.checker.hash_directory(self.temp_dir)
        self.assertEqual(len(results), 2)

    def test_hash_directory_non_recursive(self):
        """Non-recursive directory hashing."""
        subdir = os.path.join(self.temp_dir, "subdir")
        os.makedirs(subdir)
        with open(os.path.join(subdir, "nested.txt"), "w") as f:
            f.write("nested")

        results = self.checker.hash_directory(
            self.temp_dir, recursive=False
        )
        self.assertEqual(len(results), 2)  # Only top-level files

    def test_hash_directory_recursive(self):
        """Recursive directory hashing includes nested files."""
        subdir = os.path.join(self.temp_dir, "subdir")
        os.makedirs(subdir)
        with open(os.path.join(subdir, "nested.txt"), "w") as f:
            f.write("nested")

        results = self.checker.hash_directory(
            self.temp_dir, recursive=True
        )
        self.assertEqual(len(results), 3)

    def test_hash_directory_pattern_filter(self):
        """Pattern filtering limits which files are hashed."""
        os.makedirs(os.path.join(self.temp_dir, "subdir"))
        with open(os.path.join(self.temp_dir, "data.csv"), "w") as f:
            f.write("a,b,c")
        with open(os.path.join(self.temp_dir, "subdir", "data.csv"), "w") as f:
            f.write("d,e,f")

        results = self.checker.hash_directory(
            self.temp_dir, pattern="*.csv", recursive=True
        )
        self.assertEqual(len(results), 2)

    def test_hash_directory_not_found(self):
        """Non-existent directory returns empty list."""
        results = self.checker.hash_directory("/nonexistent")
        self.assertEqual(results, [])

    def test_different_algorithms(self):
        """Test all supported algorithms."""
        for algo in SUPPORTED_ALGORITHMS:
            checker = HashChecker(algorithm=algo)
            result = checker.hash_file(self.test_file)
            self.assertIsNotNone(result)
            self.assertEqual(result.algorithm, algo)

    def test_invalid_algorithm(self):
        """Invalid algorithm raises ValueError."""
        with self.assertRaises(ValueError):
            HashChecker(algorithm="invalid_algo")

    def test_get_summary_with_data(self):
        """Summary should reflect hashing activity."""
        self.checker.hash_file(self.test_file)
        summary = self.checker.get_summary()
        self.assertEqual(summary["total_files"], 1)
        self.assertIn("sha256", summary["algorithms_used"])

    def test_get_summary_empty(self):
        """Empty history should return 'No data'."""
        checker = HashChecker()
        summary = checker.get_summary()
        self.assertEqual(summary["status"], "No data")

    def test_save_report(self):
        """Save report should create a JSON file."""
        self.checker.hash_file(self.test_file)
        report_path = os.path.join(self.temp_dir, "report.json")
        saved = self.checker.save_report(report_path)
        self.assertTrue(os.path.exists(saved))
        with open(saved) as f:
            data = json.load(f)
        self.assertEqual(data["summary"]["total_files"], 1)

    def test_generate_checksum_file(self):
        """Generate a checksum file in coreutils format."""
        output = os.path.join(self.temp_dir, "checksums.sha256")
        count = self.checker.generate_checksum_file(
            self.temp_dir, output, pattern="*"
        )
        self.assertGreater(count, 0)
        self.assertTrue(os.path.exists(output))

        # Verify format
        with open(output) as f:
            content = f.read()
        self.assertIn("  test.txt", content)
        self.assertIn("  test.bin", content)

    def test_verify_checksum_file_valid(self):
        """Verify a valid checksum file."""
        output = os.path.join(self.temp_dir, "checksums.sha256")
        self.checker.generate_checksum_file(self.temp_dir, output)

        report = self.checker.verify_checksum_file(output)
        self.assertEqual(report.verified, report.total_files)
        self.assertEqual(report.mismatches, 0)
        self.assertEqual(report.missing, 0)

    def test_verify_checksum_file_mismatch(self):
        """Detect file modification via checksum mismatch."""
        output = os.path.join(self.temp_dir, "checksums.sha256")
        self.checker.generate_checksum_file(self.temp_dir, output)

        # Modify a file
        with open(self.test_file, "a") as f:
            f.write("modified")

        report = self.checker.verify_checksum_file(output)
        self.assertGreater(report.mismatches, 0)

    def test_verify_checksum_file_missing(self):
        """Detect missing files."""
        output = os.path.join(self.temp_dir, "checksums.sha256")
        self.checker.generate_checksum_file(self.temp_dir, output)

        # Delete a file
        os.remove(self.test_binary)

        report = self.checker.verify_checksum_file(output)
        self.assertGreater(report.missing, 0)

    def test_verify_checksum_file_not_found(self):
        """Non-existent checksum file returns error report."""
        report = self.checker.verify_checksum_file("/nonexistent.sha256")
        self.assertEqual(report.errors, 1)
        self.assertEqual(report.total_files, 0)

    def test_verify_checksum_empty(self):
        """Empty checksum file returns zero-verified report."""
        empty_file = os.path.join(self.temp_dir, "empty.sha256")
        Path(empty_file).write_text("")
        report = self.checker.verify_checksum_file(empty_file)
        self.assertEqual(report.total_files, 0)
        self.assertEqual(report.verified, 0)

    def test_algorithm_detection_from_filename(self):
        """Algorithm should be auto-detected from checksum filename."""
        output = os.path.join(self.temp_dir, "checksums.sha512")
        checker = HashChecker(algorithm="sha512")
        checker.generate_checksum_file(self.temp_dir, output)

        # Verify with sha256 checker (should auto-detect sha512)
        checker2 = HashChecker(algorithm="sha256")
        report = checker2.verify_checksum_file(output)
        self.assertEqual(report.algorithm, "sha512")

    def test_thread_safety(self):
        """Concurrent hashing should produce consistent results."""
        # Create many small files
        for i in range(20):
            with open(os.path.join(self.temp_dir, f"file_{i}.txt"), "w") as f:
                f.write(f"content_{i}" * 10)

        checker = HashChecker(workers=8)
        results = checker.hash_directory(self.temp_dir)
        self.assertEqual(len(results), 22)  # 20 new + 2 original

    def test_exclude_directories(self):
        """Excluded directories should be skipped."""
        cache_dir = os.path.join(self.temp_dir, "__pycache__")
        os.makedirs(cache_dir)
        with open(os.path.join(cache_dir, "cached.py"), "w") as f:
            f.write("cached")

        results = self.checker.hash_directory(
            self.temp_dir, exclude_dirs={"__pycache__"}
        )
        self.assertEqual(len(results), 2)  # No cached file

    def test_verification_report_dataclass(self):
        """VerificationReport stores all fields correctly."""
        report = VerificationReport(
            checksum_file="test.sha256",
            algorithm="sha256",
            total_files=10,
            verified=8,
            mismatches=1,
            missing=1,
            errors=0,
            duration_seconds=1.5,
            timestamp=1234567890.0,
            details=[{"file": "test.txt", "status": "verified"}]
        )
        self.assertEqual(report.total_files, 10)
        self.assertEqual(report.verified, 8)
        self.assertEqual(report.duration_seconds, 1.5)


if __name__ == '__main__':
    unittest.main()