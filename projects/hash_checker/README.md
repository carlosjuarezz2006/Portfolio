# HashChecker

A file integrity verification tool that computes, verifies, and manages file hashes using SHA-256, SHA-512, BLAKE2b, and MD5. Supports recursive directory scanning, checksum file generation, batch verification, and structured reporting.

## Features
- **Multiple Hash Algorithms**: SHA-256, SHA-512, BLAKE2b, and MD5 (legacy).
- **Recursive Directory Scanning**: Hash all files in a directory tree with glob pattern filtering.
- **Checksum File Generation**: Produces GNU coreutils-compatible format (sha256sum/sha512sum).
- **Batch Verification**: Verify file integrity against existing checksum files.
- **Concurrent Processing**: Thread pool parallelism for fast hashing of large file sets.
- **Excluded Directories**: Automatically skips `.git`, `__pycache__`, `node_modules`, and more.
- **Structured Reports**: `VerificationReport` dataclass with JSON export and summary statistics.
- **Streaming Reads**: Buffer-based file reading for memory-efficient handling of large files.
- **Algorithm Auto-Detection**: Automatically detects the hash algorithm from checksum filenames.

## Grok Build Standards
- **Cryptographic Security**: Uses `hashlib` with SHA-256/SHA-512/BLAKE2b (no deprecated algorithms).
- **OOP Architecture**: Clean separation with `HashChecker`, `FileHash`, and `VerificationReport` classes.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 25+ unit tests.

## Usage
```python
from hash_checker import HashChecker

checker = HashChecker(algorithm="sha256", workers=4)

# Hash a single file
result = checker.hash_file("document.pdf")
print(f"Hash: {result.hash_value}")

# Hash all files in a directory recursively
results = checker.hash_directory("./files", pattern="*", recursive=True)
print(f"Hashed {len(results)} files")

# Generate a checksum file (sha256sum compatible)
count = checker.generate_checksum_file("./files", "checksums.sha256")

# Verify integrity against a checksum file
report = checker.verify_checksum_file("checksums.sha256")
print(f"Verified: {report.verified}/{report.total_files}")
print(f"Mismatches: {report.mismatches}")

# Get summary
summary = checker.get_summary()

# Save report
checker.save_report("integrity_report.json")
```

## CLI Usage
```bash
# Hash a single file
python hash_checker.py hash document.pdf

# Hash a directory recursively
python hash_checker.py hash ./files --pattern "*.py"

# Generate checksum file
python hash_checker.py checksum ./files -o checksums.sha256

# Verify against checksum file
python hash_checker.py verify checksums.sha256

# Use different algorithm
python hash_checker.py hash data.bin -a sha512

# Show summary
python hash_checker.py summary
```

## Supported Algorithms
| Algorithm | Hash Length | Use Case |
|-----------|-------------|----------|
| `sha256` | 64 hex chars | General purpose integrity |
| `sha512` | 128 hex chars | High-security environments |
| `blake2b` | 128 hex chars | Modern high-speed hashing |
| `md5` | 32 hex chars | Legacy compatibility only |

## Checksum File Format
The generated checksum files follow the GNU coreutils format:
```
<hash>  <relative_file_path>
```
This format is compatible with `sha256sum`, `sha512sum`, `md5sum`, and `b2sum`. Example:
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  document.pdf
a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3  config.json
```