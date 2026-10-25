"""Public behavior tests for binary."""

import subprocess
from unittest.mock import patch

import pytest
from pydantic import TypeAdapter

from tests.fixtures import binary


class TestBuildNeoproxyBinary:
    """Tests for integration-test binary build selection."""

    def test_build_uses_default_features(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEOPROXY_BINARY", raising=False)
        monkeypatch.delenv("NEOPROXY_CARGO_FEATURES", raising=False)

        with patch.object(subprocess, "run") as mock_run:
            binary.build_neoproxy_binary()

        cmd = TypeAdapter(list[str]).validate_python(mock_run.call_args[0][0])
        assert cmd == ["cargo", "build"]

    def test_build_allows_explicit_features(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("NEOPROXY_BINARY", raising=False)
        monkeypatch.setenv("NEOPROXY_CARGO_FEATURES", "tls-openssl")

        with patch.object(subprocess, "run") as mock_run:
            binary.build_neoproxy_binary()

        cmd = TypeAdapter(list[str]).validate_python(mock_run.call_args[0][0])
        assert cmd == ["cargo", "build", "--features", "tls-openssl"]
