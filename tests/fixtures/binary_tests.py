"""Public contracts for the integration-test artifact."""

from pathlib import Path

import pytest

from tests.fixtures.binary import check_binary_exists


@pytest.mark.parametrize("present", [False, True])
def test_check_binary_exists_requires_file(tmp_path: Path, present: bool) -> None:
    artifact = tmp_path / "neoproxy"
    if present:
        artifact.touch()
    assert check_binary_exists(artifact) is present


def test_check_binary_exists_rejects_directory(tmp_path: Path) -> None:
    assert not check_binary_exists(tmp_path)
