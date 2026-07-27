"""
CodeScrutiny: A professional Python code quality analyzer.
===========================================================
Scans Python source files and produces metrics: lines of code,
function/class counts, docstring coverage, type hint coverage,
cyclomatic complexity estimation, and generates structured reports.

Grok Build Standards:
- OOP: Clean separation of concerns with dedicated analyzer classes
- Security: No code execution — pure AST-based static analysis
- Documentation: Full type hints, comprehensive docstrings, structured logging
"""

import ast
import os
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict, field
from pathlib import Path
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CodeScrutiny")


@dataclass
class FileMetrics:
    """Data class holding all quality metrics for a single file."""
    file_path: str
    relative_path: str
    total_lines: int
    code_lines: int
    comment_lines: int
    blank_lines: int
    function_count: int
    class_count: int
    methods_count: int
    docstring_count: int
    type_hint_count: int
    avg_function_length: float
    max_function_length: int
    max_complexity: int
    avg_complexity: float
    docstring_coverage: float
    type_hint_coverage: float
    has_main_guard: bool
    imports: int
    issues: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    @property
    def quality_score(self) -> float:
        """
        Calculate a 0-100 quality score based on aggregated metrics.

        Weighting:
        - Docstring coverage: 25 points
        - Type hint coverage: 25 points
        - Low complexity: 20 points
        - Reasonable function length: 15 points
        - Code-to-comment ratio: 15 points
        """
        score = 0.0

        # Docstring coverage (0-25)
        score += min(self.docstring_coverage * 25, 25)

        # Type hint coverage (0-25)
        score += min(self.type_hint_coverage * 25, 25)

        # Complexity score (0-20) — lower is better
        if self.max_complexity <= 5:
            score += 20
        elif self.max_complexity <= 10:
            score += 15
        elif self.max_complexity <= 15:
            score += 10
        elif self.max_complexity <= 20:
            score += 5

        # Function length score (0-15) — shorter is better
        if self.avg_function_length <= 10:
            score += 15
        elif self.avg_function_length <= 20:
            score += 12
        elif self.avg_function_length <= 30:
            score += 8
        elif self.avg_function_length <= 50:
            score += 4

        # Comment ratio score (0-15)
        if self.total_lines > 0:
            comment_ratio = self.comment_lines / self.total_lines
            if comment_ratio >= 0.15:
                score += 15
            elif comment_ratio >= 0.10:
                score += 10
            elif comment_ratio >= 0.05:
                score += 5

        return round(score, 2)


@dataclass
class ProjectSummary:
    """Aggregate summary for an entire project scan."""
    project_root: str
    total_files: int
    total_lines: int
    total_code_lines: int
    total_issues: int
    avg_quality_score: float
    min_quality_score: float
    max_quality_score: float
    files_by_score: Dict[str, List[str]]
    timestamp: float = field(default_factory=time.time)


class ComplexityVisitor(ast.NodeVisitor):
    """
    AST visitor that computes McCabe-style cyclomatic complexity
    for a single function or method.
    """

    def __init__(self):
        self.complexity = 1  # Base complexity

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        # Each except block adds complexity
        self.complexity += len(node.handlers)
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # Each boolean operator adds complexity
        self.complexity += len(node.values) - 1
        self.generic_visit(node)


class FunctionAnalyzer(ast.NodeVisitor):
    """
    AST visitor that collects metrics on functions and methods.
    """

    def __init__(self):
        self.functions: List[Dict[str, Any]] = []
        self.classes: List[Dict[str, Any]] = []
        self.current_class: Optional[str] = None
        self.docstring_count = 0
        self.type_hint_count = 0
        self.imports = 0
        self.has_main_guard = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze class definitions."""
        methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.classes.append({
            "name": node.name,
            "line": node.lineno,
            "methods": len(methods),
            "has_docstring": ast.get_docstring(node) is not None
        })
        if ast.get_docstring(node) is not None:
            self.docstring_count += 1

        # Check method type hints
        for method in methods:
            if method.returns:
                self.type_hint_count += 1
            for arg in method.args.args:
                if arg.annotation:
                    self.type_hint_count += 1

        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function definitions."""
        self._analyze_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze async function definitions."""
        self._analyze_function(node)
        self.generic_visit(node)

    def _analyze_function(self, node: ast.FunctionDef) -> None:
        """Common analysis for both sync and async functions."""
        # Calculate complexity
        comp_visitor = ComplexityVisitor()
        comp_visitor.visit(node)

        # Count lines
        if hasattr(node, 'end_lineno') and node.end_lineno:
            line_count = node.end_lineno - node.lineno + 1
        else:
            line_count = 0

        has_docstring = ast.get_docstring(node) is not None
        if has_docstring:
            self.docstring_count += 1

        # Count type hints
        hints = 0
        if node.returns:
            hints += 1
        for arg in node.args.args:
            if arg.annotation:
                hints += 1
        self.type_hint_count += hints

        self.functions.append({
            "name": node.name,
            "line": node.lineno,
            "lines": line_count,
            "complexity": comp_visitor.complexity,
            "has_docstring": has_docstring,
            "type_hints": hints,
            "in_class": self.current_class is not None
        })

    def visit_Import(self, node: ast.Import) -> None:
        """Count import statements."""
        self.imports += len(node.names)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Count from-import statements."""
        self.imports += len(node.names)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        """Detect if __name__ == '__main__' guard."""
        if (isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "__main__"):
            self.has_main_guard = True
        self.generic_visit(node)


class CodeScrutiny:
    """
    Main analyzer class. Scans Python files in a directory tree,
    computes per-file metrics, and generates aggregate reports.
    """

    def __init__(self, root_path: str = ".", exclude_dirs: Optional[List[str]] = None):
        self.root_path = os.path.abspath(root_path)
        self.exclude_dirs = exclude_dirs or [
            ".git", "__pycache__", ".venv", "venv", "env",
            "node_modules", ".egg-info", "dist", "build"
        ]
        self.results: Dict[str, FileMetrics] = {}
        self.history: List[Dict] = []

    def _should_exclude(self, dir_path: str) -> bool:
        """Check if a directory should be excluded from scanning."""
        dir_name = os.path.basename(dir_path)
        return dir_name in self.exclude_dirs or dir_name.startswith(".")

    def _analyze_file(self, file_path: str) -> Optional[FileMetrics]:
        """
        Analyze a single Python file and return its metrics.
        Returns None if the file cannot be parsed.
        """
        rel_path = os.path.relpath(file_path, self.root_path)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
        except (UnicodeDecodeError, IOError) as e:
            logger.warning(f"Cannot read {file_path}: {e}")
            return None

        # Line counts
        lines = source.splitlines()
        total_lines = len(lines)
        code_lines = 0
        comment_lines = 0
        blank_lines = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                blank_lines += 1
            elif stripped.startswith('#'):
                comment_lines += 1
            else:
                code_lines += 1

        # AST analysis
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            return FileMetrics(
                file_path=file_path,
                relative_path=rel_path,
                total_lines=total_lines,
                code_lines=code_lines,
                comment_lines=comment_lines,
                blank_lines=blank_lines,
                function_count=0,
                class_count=0,
                methods_count=0,
                docstring_count=0,
                type_hint_count=0,
                avg_function_length=0.0,
                max_function_length=0,
                max_complexity=0,
                avg_complexity=0.0,
                docstring_coverage=0.0,
                type_hint_coverage=0.0,
                has_main_guard=False,
                imports=0,
                issues=[f"Syntax error: {e}"]
            )

        analyzer = FunctionAnalyzer()
        analyzer.visit(tree)

        # Classify functions as standalone vs methods
        standalone_funcs = [f for f in analyzer.functions if not f["in_class"]]
        class_methods = [f for f in analyzer.functions if f["in_class"]]

        # Calculate metrics
        func_count = len(standalone_funcs)
        class_count = len(analyzer.classes)
        methods_count = len(class_methods)

        # Function lengths
        all_func_lengths = [f["lines"] for f in analyzer.functions]
        avg_length = sum(all_func_lengths) / len(all_func_lengths) if all_func_lengths else 0.0
        max_length = max(all_func_lengths) if all_func_lengths else 0

        # Complexity
        all_complexities = [f["complexity"] for f in analyzer.functions]
        max_complexity = max(all_complexities) if all_complexities else 0
        avg_complexity = sum(all_complexities) / len(all_complexities) if all_complexities else 0.0

        # Coverage ratios
        total_functions = func_count + methods_count
        docstring_coverage = analyzer.docstring_count / total_functions if total_functions > 0 else 1.0

        # Type hint coverage: count functions with at least one type hint
        funcs_with_hints = sum(1 for f in analyzer.functions if f["type_hints"] > 0)
        type_hint_coverage = funcs_with_hints / total_functions if total_functions > 0 else 1.0

        # Generate issues
        issues = []
        if max_complexity > 15:
            issues.append(f"High cyclomatic complexity ({max_complexity}) — consider refactoring")
        if max_length > 80:
            issues.append(f"Long function detected ({max_length} lines) — consider splitting")
        if not analyzer.has_main_guard and total_lines > 50:
            issues.append("Missing `if __name__ == '__main__'` guard")
        if docstring_coverage < 0.5:
            issues.append(f"Low docstring coverage ({docstring_coverage:.0%})")
        if type_hint_coverage < 0.3:
            issues.append(f"Low type hint coverage ({type_hint_coverage:.0%})")

        metrics = FileMetrics(
            file_path=file_path,
            relative_path=rel_path,
            total_lines=total_lines,
            code_lines=code_lines,
            comment_lines=comment_lines,
            blank_lines=blank_lines,
            function_count=func_count,
            class_count=class_count,
            methods_count=methods_count,
            docstring_count=analyzer.docstring_count,
            type_hint_count=analyzer.type_hint_count,
            avg_function_length=round(avg_length, 2),
            max_function_length=max_length,
            max_complexity=max_complexity,
            avg_complexity=round(avg_complexity, 2),
            docstring_coverage=round(docstring_coverage, 4),
            type_hint_coverage=round(type_hint_coverage, 4),
            has_main_guard=analyzer.has_main_guard,
            imports=analyzer.imports,
            issues=issues
        )

        logger.info(
            f"Analyzed {rel_path} — "
            f"Score: {metrics.quality_score}/100, "
            f"Functions: {func_count}, Classes: {class_count}, "
            f"Max complexity: {max_complexity}"
        )
        return metrics

    def scan_directory(self, path: Optional[str] = None) -> Dict[str, FileMetrics]:
        """
        Recursively scan a directory for Python files and analyze them.

        Args:
            path: Directory to scan (defaults to root_path)

        Returns:
            Dict mapping relative file paths to FileMetrics objects.
        """
        scan_path = path or self.root_path
        self.results = {}
        py_files = []

        for root, dirs, files in os.walk(scan_path):
            # Filter excluded directories
            dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d))]
            for f in files:
                if f.endswith(".py"):
                    py_files.append(os.path.join(root, f))

        if not py_files:
            logger.warning(f"No Python files found in {scan_path}")
            return {}

        logger.info(f"Found {len(py_files)} Python files to analyze")

        for file_path in sorted(py_files):
            metrics = self._analyze_file(file_path)
            if metrics:
                self.results[metrics.relative_path] = metrics

        return self.results

    def get_summary(self) -> ProjectSummary:
        """
        Generate an aggregate project summary from all scanned files.
        """
        if not self.results:
            return ProjectSummary(
                project_root=self.root_path,
                total_files=0,
                total_lines=0,
                total_code_lines=0,
                total_issues=0,
                avg_quality_score=0.0,
                min_quality_score=0.0,
                max_quality_score=0.0,
                files_by_score={}
            )

        scores = [m.quality_score for m in self.results.values()]
        total_issues = sum(len(m.issues) for m in self.results.values())
        total_lines = sum(m.total_lines for m in self.results.values())
        total_code = sum(m.code_lines for m in self.results.values())

        # Categorize files by score range
        files_by_score: Dict[str, List[str]] = {
            "excellent (90-100)": [],
            "good (70-89)": [],
            "fair (50-69)": [],
            "needs_improvement (0-49)": []
        }
        for rel_path, metrics in self.results.items():
            score = metrics.quality_score
            if score >= 90:
                files_by_score["excellent (90-100)"].append(rel_path)
            elif score >= 70:
                files_by_score["good (70-89)"].append(rel_path)
            elif score >= 50:
                files_by_score["fair (50-69)"].append(rel_path)
            else:
                files_by_score["needs_improvement (0-49)"].append(rel_path)

        return ProjectSummary(
            project_root=self.root_path,
            total_files=len(self.results),
            total_lines=total_lines,
            total_code_lines=total_code,
            total_issues=total_issues,
            avg_quality_score=round(sum(scores) / len(scores), 2),
            min_quality_score=round(min(scores), 2),
            max_quality_score=round(max(scores), 2),
            files_by_score=files_by_score
        )

    def save_report(self, filename: str = "code_scrutiny_report.json") -> bool:
        """
        Save the current scan results to a JSON report file.

        Returns True on success, False on failure.
        """
        if not self.results:
            logger.warning("No results to save")
            return False

        try:
            summary = self.get_summary()
            report = {
                "summary": asdict(summary),
                "files": {
                    rel_path: asdict(metrics)
                    for rel_path, metrics in sorted(self.results.items())
                }
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Report saved to {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False

    def print_summary_table(self) -> None:
        """Print a formatted summary table to stdout."""
        summary = self.get_summary()

        print("=" * 60)
        print("  CODESCRUTINY — QUALITY REPORT")
        print("=" * 60)
        print(f"  Project Root : {summary.project_root}")
        print(f"  Files Scanned: {summary.total_files}")
        print(f"  Total Lines  : {summary.total_lines}")
        print(f"  Code Lines   : {summary.total_code_lines}")
        print(f"  Total Issues : {summary.total_issues}")
        print(f"  Avg Score    : {summary.avg_quality_score}/100")
        print(f"  Min Score    : {summary.min_quality_score}/100")
        print(f"  Max Score    : {summary.max_quality_score}/100")
        print("-" * 60)
        print("  Score Distribution:")
        for category, files in summary.files_by_score.items():
            if files:
                print(f"    {category}: {len(files)} file(s)")
                for f in files:
                    score = self.results[f].quality_score
                    print(f"      {score:>5}/100  {f}")
        print("=" * 60)

        # Print files with issues
        files_with_issues = {p: m for p, m in self.results.items() if m.issues}
        if files_with_issues:
            print("\n  Files with Issues:")
            for rel_path, metrics in sorted(files_with_issues.items()):
                print(f"    {rel_path} ({metrics.quality_score}/100):")
                for issue in metrics.issues:
                    print(f"      ⚠ {issue}")


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    exclude = sys.argv[2:] if len(sys.argv) > 2 else None

    print(f"CodeScrutiny analyzing: {os.path.abspath(target)}")
    scrutiny = CodeScrutiny(root_path=target)
    scrutiny.scan_directory()
    scrutiny.print_summary_table()
    scrutiny.save_report()