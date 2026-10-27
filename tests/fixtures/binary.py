"""Locate the prebuilt integration-test artifact.

Public operations: check_binary_exists; data: PROJECT_ROOT, NEOPROXY_BINARY.
Tests: binary_tests.py.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NEOPROXY_BINARY = str(PROJECT_ROOT / "target" / "debug" / "neoproxy")


def check_binary_exists(path: Path | None = None) -> bool:
    """Require an existing artifact file without building it."""
    return (Path(NEOPROXY_BINARY) if path is None else path).is_file()
