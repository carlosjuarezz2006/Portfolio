# CodeScrutiny

A professional Python code quality analyzer that performs static analysis on Python source files using AST (Abstract Syntax Tree) parsing.

## Features
- **AST-Based Analysis**: No code execution — pure static analysis for safety.
- **Comprehensive Metrics**: Lines of code, function/class counts, docstring coverage, type hint coverage, cyclomatic complexity.
- **Complexity Scoring**: Identifies functions with high cyclomatic complexity (configurable threshold, defaults to 10).
- **Rule Violations**: Detects missing docstrings, missing type hints, long functions, global variables, and bare except clauses.
- **Structured Reports**: JSON export with per-file and aggregate statistics.
- **Summary Table**: Console output with color-coded health indicators.

## Grok Build Standards
- **OOP Architecture**: Clean separation with `CodeScrutiny`, `FileMetrics`, and `ComplexityVisitor` classes.
- **Security**: No code execution — pure AST-based static analysis.
- **Documentation**: Full type hints, comprehensive docstrings, structured logging, and 20+ unit tests.

## Usage
```python
from code_scrutiny import CodeScrutiny

scrutiny = CodeScrutiny(root_path="./my_project")
scrutiny.scan_directory()
scrutiny.print_summary_table()
scrutiny.save_report("code_quality_report.json")
```

## CLI Usage
```bash
python code_scrutiny.py .                     # Scan current directory
python code_scrutiny.py projects/system_guard  # Scan specific directory
python code_scrutiny.py . --exclude tests      # Exclude test files
```

## Metrics
| Metric | Description |
|--------|-------------|
| LOC | Lines of code (excluding blanks/comments) |
| Functions | Number of function definitions |
| Classes | Number of class definitions |
| Docstring % | Percentage of functions/classes with docstrings |
| Type Hint % | Percentage of functions with type hints |
| Max Complexity | Highest cyclomatic complexity in the file |
| Violations | Count of rule violations detected |