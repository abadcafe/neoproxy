"""Public pytest collection contracts for integration-test scheduling."""

import subprocess
import sys
from pathlib import Path


def test_collection_starts_slow_cases_before_short_cases(tmp_path: Path) -> None:
    case = tmp_path / "test_scheduling.py"
    _ = case.write_text("""import pytest

def test_fast_first() -> None:
    pass

@pytest.mark.slow
def test_slow_first() -> None:
    pass

def test_fast_second() -> None:
    pass

@pytest.mark.slow
def test_slow_second() -> None:
    pass
""")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "--noconftest",
            "-p",
            "tests.conftest",
            "-o",
            "addopts=",
            "-q",
            str(case),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    names = [
        line.rsplit("::", 1)[1]
        for line in result.stdout.splitlines()
        if "::test_" in line
    ]
    assert names == [
        "test_slow_first",
        "test_slow_second",
        "test_fast_first",
        "test_fast_second",
    ]
