"""
HashChecker: A file integrity verification tool.
===================================================
Computes, verifies, and manages file hashes using SHA-256, SHA-512,
BLAKE2b, and MD5 (for legacy compatibility). Supports recursive directory
scanning, checksum file generation, batch verification, and structured
reporting with JSON export.

Grok Build Standards:
- Cryptographic Security: Uses hashlib with SHA-256/SHA-512/BLAKE2b
- OOP: Clean separation with HashChecker, FileHash, VerificationReport
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import os
import hashlib
import logging
import json
import time
import sys
from typing import Dict, List, Optional, Iterator, Tuple, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("HashChecker")

# Supported hash algorithms
SUPPORTED_ALGORITHMS: Dict[str, callable] = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "blake2b": hashlib.blake2b,
    "md5": hashlib.md5,
}

# Buffer size for streaming file reads (64KB)
BUFFER_SIZE = 65536


@dataclass
class FileHash:
    """Represents a computed hash for a single file."""
    file_path: str
    algorithm: str
    hash_value: str
    file_size_bytes: int
    computed_at: float
    status: str = "computed"  # computed, verified, failed, mismatch


@dataclass
class VerificationReport:
    """Aggregated report for a checksum verification operation."""
    checksum_file: str
    algorithm: str
    total_files: int
    verified: int
    mismatches: int
    missing: int
    errors: int
    duration_seconds: float
    timestamp: float
    details: List[Dict] = field(default_factory=list)


class HashChecker:
    """
    A professional file integrity verification tool.

    Computes cryptographic hashes for files, generates checksum files
    (compatible with sha256sum/sha512sum format), and verifies file
    integrity against existing checksums.

    Features:
    - Multiple hash algorithms: SHA-256, SHA-512, BLAKE2b, MD5
    - Recursive directory scanning with glob/filter support
    - Checksum file generation (GNU coreutils compatible format)
    - Batch verification against existing checksum files
    - Concurrent processing for performance
    - Summary and JSON export

    Usage:
        checker = HashChecker()
        results = checker.hash_file("document.pdf")
        results = checker.hash_directory("./files", recursive=True)
        checker.generate_checksum_file("./files", "checksums.sha256")
        report = checker.verify_checksum_file("checksums.sha256")
    """

    def __init__(
        self,
        algorithm: str = "sha256",
        workers: int = 4,
        buffer_size: int = BUFFER_SIZE
    ):
        """
        Initialize HashChecker.

        Args:
            algorithm: Hash algorithm to use (sha256, sha512, blake2b, md5).
            workers: Number of concurrent workers for processing.
            buffer_size: Read buffer size in bytes.

        Raises:
            ValueError: If algorithm is not supported.
        """
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported: {', '.join(SUPPORTED_ALGORITHMS.keys())}"
            )
        self.algorithm = algorithm
        self.workers = max(1, min(workers, os.cpu_count() or 4))
        self.buffer_size = buffer_size
        self.history: List[FileHash] = []
        logger.info(
            "HashChecker initialized: algorithm=%s, workers=%d",
            algorithm, self.workers
        )

    def _hash_file(self, file_path: str) -> Optional[FileHash]:
        """
        Compute the hash of a single file using streaming reads.

        Uses a buffer to handle large files without loading them entirely
        into memory. Returns None if the file does not exist or is not
        readable.

        Args:
            file_path: Absolute or relative path to the file.

        Returns:
            FileHash object or None on failure.
        """
        path = Path(file_path)
        if not path.is_file():
            logger.warning("File not found: %s", file_path)
            return None

        try:
            hasher = SUPPORTED_ALGORITHMS[self.algorithm]()
            file_size = path.stat().st_size

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break
                    hasher.update(chunk)

            hash_value = hasher.hexdigest()
            result = FileHash(
                file_path=str(path.resolve()),
                algorithm=self.algorithm,
                hash_value=hash_value,
                file_size_bytes=file_size,
                computed_at=time.time(),
                status="computed"
            )
            self.history.append(result)
            return result

        except PermissionError:
            logger.error("Permission denied: %s", file_path)
            return None
        except OSError as e:
            logger.error("OS error reading %s: %s", file_path, e)
            return None

    def hash_file(self, file_path: str) -> Optional[FileHash]:
        """
        Compute the hash of a single file.

        Args:
            file_path: Path to the file.

        Returns:
            FileHash object or None on failure.
        """
        return self._hash_file(file_path)

    def hash_directory(
        self,
        directory: str,
        pattern: str = "*",
        recursive: bool = True,
        exclude_dirs: Optional[Set[str]] = None
    ) -> List[FileHash]:
        """
        Compute hashes for all files in a directory matching a pattern.

        Uses concurrent workers for parallel processing. Filters out
        common binary/cache directories by default.

        Args:
            directory: Root directory to scan.
            pattern: Glob pattern for file matching (default: all files).
            recursive: Whether to scan subdirectories.
            exclude_dirs: Set of directory names to exclude.

        Returns:
            List of FileHash objects for successfully hashed files.
        """
        root = Path(directory)
        if not root.is_dir():
            logger.error("Directory not found: %s", directory)
            return []

        exclude_dirs = exclude_dirs or {
            ".git", "__pycache__", ".venv", "node_modules",
            ".cache", ".tox", "venv", ".eggs"
        }

        # Collect files
        files_to_hash: List[Path] = []
        if recursive:
            for path in root.rglob(pattern):
                if path.is_file():
                    # Check if any parent is excluded
                    if not any(
                        part in exclude_dirs for part in path.relative_to(root).parts
                    ):
                        files_to_hash.append(path)
        else:
            for path in root.glob(pattern):
                if path.is_file():
                    files_to_hash.append(path)

        if not files_to_hash:
            logger.info("No files found matching pattern '%s' in %s", pattern, directory)
            return []

        logger.info(
            "Hashing %d files in %s (workers=%d)...",
            len(files_to_hash), directory, self.workers
        )

        # Process with thread pool
        results: List[FileHash] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_map = {
                executor.submit(self._hash_file, str(f)): f
                for f in files_to_hash
            }
            for future in as_completed(future_map):
                result = future.result()
                if result:
                    results.append(result)

        logger.info("Completed: %d/%d files hashed", len(results), len(files_to_hash))
        return results

    def generate_checksum_file(
        self,
        directory: str,
        output_file: str,
        pattern: str = "*",
        recursive: bool = True,
        algorithm: Optional[str] = None
    ) -> int:
        """
        Generate a checksum file (GNU coreutils format).

        Produces a file in the format:
            <hash>  <relative_file_path>

        This format is compatible with sha256sum, sha512sum, md5sum, etc.

        Args:
            directory: Directory to scan for files.
            output_file: Path to the output checksum file.
            pattern: Glob pattern for file matching.
            recursive: Whether to scan subdirectories.
            algorithm: Override the default algorithm for this operation.

        Returns:
            Number of files included in the checksum file.
        """
        if algorithm and algorithm not in SUPPORTED_ALGORITHMS:
            logger.error("Unsupported algorithm: %s", algorithm)
            return 0

        orig_algorithm = self.algorithm
        if algorithm:
            self.algorithm = algorithm

        try:
            results = self.hash_directory(directory, pattern, recursive)
            if not results:
                return 0

            root = Path(directory).resolve()
            output_path = Path(output_file)

            lines = []
            for fh in sorted(results, key=lambda x: x.file_path):
                try:
                    rel_path = Path(fh.file_path).relative_to(root)
                    lines.append(f"{fh.hash_value}  {rel_path}")
                except ValueError:
                    # File outside root, use absolute path
                    lines.append(f"{fh.hash_value}  {fh.file_path}")

            content = "\n".join(lines) + "\n"
            # Atomic write
            temp_path = output_path.with_suffix(".tmp")
            temp_path.write_text(content, encoding="utf-8")
            temp_path.rename(output_path)

            logger.info(
                "Checksum file generated: %s (%d files, %s)",
                output_file, len(results), algorithm or self.algorithm
            )
            return len(results)

        finally:
            self.algorithm = orig_algorithm

    def verify_checksum_file(self, checksum_file: str) -> VerificationReport:
        """
        Verify file integrity against a checksum file.

        Reads a checksum file in GNU coreutils format and verifies
        each file's hash matches the expected value.

        Args:
            checksum_file: Path to the checksum file.

        Returns:
            VerificationReport with detailed results.
        """
        start_time = time.time()
        checksum_path = Path(checksum_file)

        if not checksum_path.is_file():
            logger.error("Checksum file not found: %s", checksum_file)
            return VerificationReport(
                checksum_file=checksum_file,
                algorithm=self.algorithm,
                total_files=0, verified=0,
                mismatches=0, missing=0, errors=1,
                duration_seconds=0.0,
                timestamp=time.time()
            )

        # Detect algorithm from filename
        algo = self.algorithm
        name_lower = checksum_file.lower()
        if "sha256" in name_lower:
            algo = "sha256"
        elif "sha512" in name_lower:
            algo = "sha512"
        elif "blake2" in name_lower:
            algo = "blake2b"
        elif "md5" in name_lower:
            algo = "md5"

        # Parse checksum file
        root_dir = checksum_path.parent
        expected_hashes: List[Tuple[str, str]] = []
        total_entries = 0

        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total_entries += 1
            # Format: <hash>  <filepath> (with double space separator)
            if "  " in line:
                hash_val, filepath = line.split("  ", 1)
                expected_hashes.append((hash_val.strip(), filepath.strip()))

        if not expected_hashes:
            logger.warning("No valid entries found in checksum file")
            return VerificationReport(
                checksum_file=checksum_file,
                algorithm=algo,
                total_files=total_entries,
                verified=0, mismatches=0, missing=0, errors=0,
                duration_seconds=time.time() - start_time,
                timestamp=time.time()
            )

        # Verify each file
        details: List[Dict] = []
        verified_count = 0
        mismatch_count = 0
        missing_count = 0
        error_count = 0

        for expected_hash, rel_path in expected_hashes:
            file_path = root_dir / rel_path
            entry = {
                "file": rel_path,
                "expected_hash": expected_hash,
                "status": "",
                "actual_hash": ""
            }

            if not file_path.is_file():
                entry["status"] = "missing"
                missing_count += 1
                details.append(entry)
                continue

            try:
                # Compute actual hash
                hasher = SUPPORTED_ALGORITHMS[algo]()
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(self.buffer_size)
                        if not chunk:
                            break
                        hasher.update(chunk)
                actual_hash = hasher.hexdigest()
                entry["actual_hash"] = actual_hash

                if actual_hash == expected_hash:
                    entry["status"] = "verified"
                    verified_count += 1
                else:
                    entry["status"] = "mismatch"
                    mismatch_count += 1

            except (PermissionError, OSError) as e:
                entry["status"] = "error"
                entry["error"] = str(e)
                error_count += 1

            details.append(entry)

        duration = time.time() - start_time
        report = VerificationReport(
            checksum_file=checksum_file,
            algorithm=algo,
            total_files=total_entries,
            verified=verified_count,
            mismatches=mismatch_count,
            missing=missing_count,
            errors=error_count,
            duration_seconds=round(duration, 2),
            timestamp=time.time(),
            details=details
        )

        logger.info(
            "Verification complete: %d/%d verified, %d mismatches, "
            "%d missing, %d errors (%.2fs)",
            verified_count, total_entries, mismatch_count,
            missing_count, error_count, duration
        )
        return report

    def get_summary(self) -> Dict:
        """
        Get a summary of all hashing activity in the current session.

        Returns:
            Dictionary with summary statistics.
        """
        total = len(self.history)
        if total == 0:
            return {"status": "No data", "total_files": 0}

        total_size = sum(h.file_size_bytes for h in self.history)
        return {
            "status": "active",
            "total_files": total,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "algorithm": self.algorithm,
            "algorithms_used": list(set(h.algorithm for h in self.history)),
            "last_computed": asdict(self.history[-1]) if self.history else None
        }

    def save_report(self, filename: str = "hash_checker_report.json") -> str:
        """
        Save the current session history to a JSON file.

        Args:
            filename: Output filename.

        Returns:
            Path to the saved file.
        """
        data = {
            "summary": self.get_summary(),
            "files": [
                {k: v for k, v in asdict(h).items() if k != "hash_value"}
                for h in self.history
            ],
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Report saved to %s", filename)
        return filename


def main():
    """CLI entry point for HashChecker."""
    import argparse

    parser = argparse.ArgumentParser(
        description="HashChecker: File integrity verification tool"
    )
    parser.add_argument(
        "action",
        choices=["hash", "checksum", "verify", "summary"],
        help="Action to perform"
    )
    parser.add_argument("path", nargs="?", help="File or directory path")
    parser.add_argument(
        "-o", "--output",
        help="Output file for checksum generation or report"
    )
    parser.add_argument(
        "-a", "--algorithm",
        default="sha256",
        choices=list(SUPPORTED_ALGORITHMS.keys()),
        help="Hash algorithm (default: sha256)"
    )
    parser.add_argument(
        "--pattern",
        default="*",
        help="Glob pattern for directory scanning (default: *)"
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive directory scanning"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent workers (default: 4)"
    )

    args = parser.parse_args()

    checker = HashChecker(
        algorithm=args.algorithm,
        workers=args.workers
    )

    if args.action == "hash":
        if not args.path:
            parser.error("hash requires a file or directory path")
        path = Path(args.path)
        if path.is_dir():
            results = checker.hash_directory(
                args.path, args.pattern, not args.no_recursive
            )
            print(f"Hashed {len(results)} files in {args.path}")
        elif path.is_file():
            result = checker.hash_file(args.path)
            if result:
                print(f"File: {result.file_path}")
                print(f"Hash ({result.algorithm}): {result.hash_value}")
                print(f"Size: {result.file_size_bytes} bytes")
            else:
                print("Failed to hash file")
        else:
            print(f"Path not found: {args.path}")

    elif args.action == "checksum":
        if not args.path:
            parser.error("checksum requires a directory path")
        output = args.output or f"checksums.{args.algorithm}"
        count = checker.generate_checksum_file(
            args.path, output, args.pattern, not args.no_recursive
        )
        print(f"Generated {output} with {count} file entries")

    elif args.action == "verify":
        if not args.path:
            parser.error("verify requires a checksum file path")
        report = checker.verify_checksum_file(args.path)
        print(f"Verification Report:")
        print(f"  Algorithm: {report.algorithm}")
        print(f"  Total files: {report.total_files}")
        print(f"  Verified: {report.verified}")
        print(f"  Mismatches: {report.mismatches}")
        print(f"  Missing: {report.missing}")
        print(f"  Errors: {report.errors}")
        print(f"  Duration: {report.duration_seconds}s")
        if report.details:
            for d in report.details:
                if d["status"] in ("mismatch", "missing", "error"):
                    print(f"  [{d['status'].upper()}] {d['file']}")

    elif args.action == "summary":
        print(json.dumps(checker.get_summary(), indent=2))


if __name__ == "__main__":
    main()