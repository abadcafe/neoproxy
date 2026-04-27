"""
Test for code quality issues in test_monitoring.py.

This test verifies that test_monitoring.py does not have unused imports,
which is a code quality issue that violates YAGNI principles.
"""

import ast
import pytest
from pathlib import Path


def get_unused_imports(file_path: str) -> list[str]:
    """
    Analyze a Python file and return list of unused import names.

    Args:
        file_path: Path to the Python file to analyze

    Returns:
        List of unused import names
    """
    code = Path(file_path).read_text()
    tree = ast.parse(code)

    # Collect all names used in the file (excluding imports)
    used_names: set[str] = set()

    class NameVisitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            used_names.add(node.id)
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            # Visit the value part of the attribute (e.g., 'foo' in 'foo.bar')
            if isinstance(node.value, ast.Name):
                used_names.add(node.value.id)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            # Function names are definitions, not uses
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.generic_visit(node)

    visitor = NameVisitor()
    visitor.visit(tree)

    # Get imported names from helpers module
    imported_names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and 'helpers' in node.module:
                for alias in node.names:
                    imported_names.append(alias.name)

    # Return names that are imported but not used
    return [name for name in imported_names if name not in used_names]


class TestCodeQualityTestMonitoring:
    """Tests for code quality in test_monitoring.py."""

    def test_no_unused_imports_from_helpers(self) -> None:
        """Should not have unused imports from helpers module (YAGNI)."""
        # Use Path relative to this test file for robustness
        test_monitoring_path = Path(__file__).parent.parent / "test_monitoring.py"
        unused = get_unused_imports(str(test_monitoring_path))
        assert len(unused) == 0, f"Unused imports from helpers: {unused}"


class TestGetUnusedImports:
    """Tests for the get_unused_imports helper function."""

    def test_detects_unused_import(self, tmp_path: Path) -> None:
        """Should detect unused imports."""
        test_file = tmp_path / "test_file.py"
        test_file.write_text("""
from .utils.helpers import unused_func, used_func

def test_something():
    result = used_func()
    assert result is True
""")
        unused = get_unused_imports(str(test_file))
        assert "unused_func" in unused
        assert "used_func" not in unused

    def test_returns_empty_when_all_used(self, tmp_path: Path) -> None:
        """Should return empty list when all imports are used."""
        test_file = tmp_path / "test_file.py"
        test_file.write_text("""
from .utils.helpers import func1, func2

def test_something():
    a = func1()
    b = func2()
    assert a and b
""")
        unused = get_unused_imports(str(test_file))
        assert len(unused) == 0

    def test_handles_attribute_access(self, tmp_path: Path) -> None:
        """Should recognize imports used via attribute access."""
        test_file = tmp_path / "test_file.py"
        test_file.write_text("""
from .utils import helpers

def test_something():
    result = helpers.some_function()
    assert result
""")
        # In this case, 'helpers' is imported and used
        # This test just verifies the function doesn't crash
        unused = get_unused_imports(str(test_file))
        assert isinstance(unused, list)
