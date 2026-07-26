import unittest
import os
import tempfile
import shutil
from code_scrutiny import CodeScrutiny, FileMetrics, ComplexityVisitor


class TestComplexityVisitor(unittest.TestCase):
    """Test suite for the AST-based complexity calculator."""

    def test_base_complexity(self):
        """A simple function should have complexity 1."""
        import ast
        tree = ast.parse("def foo():\n    pass")
        visitor = ComplexityVisitor()
        visitor.visit(tree.body[0])  # visit the FunctionDef
        self.assertEqual(visitor.complexity, 1)

    def test_if_increases_complexity(self):
        """An if statement should increase complexity by 1."""
        import ast
        tree = ast.parse("def foo():\n    if True:\n        pass")
        visitor = ComplexityVisitor()
        visitor.visit(tree.body[0])
        self.assertEqual(visitor.complexity, 2)

    def test_elif_increases_complexity(self):
        """An elif statement should increase complexity by 1 per branch."""
        import ast
        tree = ast.parse("def foo(x):\n    if x > 0:\n        pass\n    elif x < 0:\n        pass")
        visitor = ComplexityVisitor()
        visitor.visit(tree.body[0])
        self.assertEqual(visitor.complexity, 3)

    def test_loop_increases_complexity(self):
        """A for loop should increase complexity by 1."""
        import ast
        tree = ast.parse("def foo():\n    for i in range(10):\n        pass")
        visitor = ComplexityVisitor()
        visitor.visit(tree.body[0])
        self.assertEqual(visitor.complexity, 2)

    def test_and_operator_increases(self):
        """Boolean 'and' operators should increase complexity."""
        import ast
        tree = ast.parse("def foo(x, y):\n    if x > 0 and y > 0:\n        pass")
        visitor = ComplexityVisitor()
        visitor.visit(tree.body[0])
        self.assertEqual(visitor.complexity, 3)  # 1 base + 1 if + 1 and


class TestCodeScrutiny(unittest.TestCase):
    """Test suite for the CodeScrutiny analyzer."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.scrutiny = CodeScrutiny(root_path=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_file(self, rel_path: str, content: str):
        full_path = os.path.join(self.test_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return full_path

    def test_empty_directory(self):
        """Scanning an empty directory should return no results."""
        results = self.scrutiny.scan_directory()
        self.assertEqual(len(results), 0)

    def test_single_file(self):
        """A single Python file should be analyzed."""
        self._write_file("test.py", "x = 1\n")
        results = self.scrutiny.scan_directory()
        self.assertEqual(len(results), 1)
        self.assertIn("test.py", results)

    def test_ignore_pycache(self):
        """__pycache__ directories should be excluded."""
        self._write_file("test.py", "x = 1\n")
        self._write_file("__pycache__/ignored.py", "y = 2\n")
        results = self.scrutiny.scan_directory()
        self.assertIn("test.py", results)
        self.assertNotIn("__pycache__/ignored.py", results)

    def test_file_metrics_class(self):
        """FileMetrics should have a quality_score property."""
        metrics = FileMetrics(
            file_path="/tmp/test.py",
            relative_path="test.py",
            total_lines=20,
            code_lines=15,
            comment_lines=2,
            blank_lines=3,
            function_count=2,
            class_count=1,
            methods_count=3,
            docstring_count=2,
            type_hint_count=5,
            avg_function_length=10.0,
            max_function_length=15,
            max_complexity=5,
            avg_complexity=3.0,
            docstring_coverage=0.8,
            type_hint_coverage=0.6,
            has_main_guard=True,
            imports=4
        )
        self.assertIsInstance(metrics.quality_score, float)
        self.assertGreaterEqual(metrics.quality_score, 0)
        self.assertLessEqual(metrics.quality_score, 100)

    def test_function_counting(self):
        """Functions should be counted correctly."""
        self._write_file("test.py", """
def func1():
    pass

def func2():
    pass

class MyClass:
    def method1(self):
        pass
""")
        results = self.scrutiny.scan_directory()
        metrics = results["test.py"]
        self.assertEqual(metrics.function_count, 2)  # standalone functions
        self.assertEqual(metrics.methods_count, 1)    # class methods
        self.assertEqual(metrics.class_count, 1)

    def test_docstring_coverage(self):
        """Files with docstrings should have higher coverage."""
        self._write_file("test.py", '''
def foo():
    """This function has a docstring."""
    pass

def bar():
    """Another docstring."""
    pass
''')
        results = self.scrutiny.scan_directory()
        self.assertEqual(results["test.py"].docstring_coverage, 1.0)

    def test_main_guard_detection(self):
        """The __name__ == '__main__' guard should be detected."""
        self._write_file("test.py", """
def main():
    pass

if __name__ == '__main__':
    main()
""")
        results = self.scrutiny.scan_directory()
        self.assertTrue(results["test.py"].has_main_guard)

    def test_missing_main_guard(self):
        """Files without a main guard should be flagged."""
        self._write_file("test.py", "x = 1\ny = 2\n")
        results = self.scrutiny.scan_directory()
        self.assertFalse(results["test.py"].has_main_guard)

    def test_syntax_error_file(self):
        """Files with syntax errors should still produce metrics."""
        self._write_file("bad.py", "def foo(:\n    pass\n")
        results = self.scrutiny.scan_directory()
        self.assertIn("bad.py", results)
        self.assertGreater(len(results["bad.py"].issues), 0)

    def test_report_saving(self):
        """The report should be saved to a JSON file."""
        self._write_file("test.py", "x = 1\n")
        self.scrutiny.scan_directory()
        report_path = os.path.join(self.test_dir, "report.json")
        result = self.scrutiny.save_report(report_path)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(report_path))

    def test_exclude_dirs(self):
        """Custom exclude directories should be respected."""
        self._write_file("src/main.py", "x = 1\n")
        self._write_file("vendor/third_party.py", "y = 2\n")
        scrutiny = CodeScrutiny(root_path=self.test_dir, exclude_dirs=["vendor"])
        results = scrutiny.scan_directory()
        self.assertIn("src/main.py", results)
        self.assertNotIn("vendor/third_party.py", results)

    def test_empty_results_summary(self):
        """Summary should handle empty results gracefully."""
        summary = self.scrutiny.get_summary()
        self.assertEqual(summary.total_files, 0)

    def test_import_counting(self):
        """Import statements should be counted."""
        self._write_file("test.py", """
import os
import sys
from datetime import datetime
""")
        results = self.scrutiny.scan_directory()
        self.assertEqual(results["test.py"].imports, 3)

    def test_complexity_detection(self):
        """High-complexity functions should be flagged."""
        self._write_file("test.py", """
def complex_function(x, y, z):
    if x > 0:
        if y > 0:
            if z > 0:
                pass
            else:
                pass
        else:
            pass
    else:
        pass
    for i in range(10):
        while True:
            break
    return True
""")
        results = self.scrutiny.scan_directory()
        self.assertGreater(results["test.py"].max_complexity, 5)


if __name__ == '__main__':
    unittest.main()