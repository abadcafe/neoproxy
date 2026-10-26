"""Command-line actions must complete before configuration or worker startup."""

import subprocess
from pathlib import Path

import pytest

from tests.fixtures.binary import NEOPROXY_BINARY


@pytest.mark.parametrize("flag", ["-v", "--version"])
def test_version_succeeds_without_a_configuration_file(
    tmp_path: Path, flag: str
) -> None:
    result = subprocess.run(
        [NEOPROXY_BINARY, "--config", "missing.yaml", flag],
        cwd=tmp_path,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(b"neoproxy ")
    assert not result.stderr
    assert not (tmp_path / "logs").exists()
