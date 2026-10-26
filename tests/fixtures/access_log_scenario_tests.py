"""Access-log configuration fixture behavior."""

import time
from pathlib import Path

import pytest
import yaml
from pydantic import TypeAdapter

from tests.fixtures.access_log_scenario import (
    AccessLogTestEnv,
    wait_for_access_log,
    write_config,
)
from tests.fixtures.configuration import ConfigDict


@pytest.mark.parametrize("jump", [-3600.0, 3600.0])
def test_wait_for_access_log_honors_duration_when_wall_clock_jumps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, jump: float
) -> None:
    calls = 0

    def discontinuous_wall_time() -> float:
        nonlocal calls
        values = (0.0, jump, abs(jump) * 2)
        value = values[min(calls, 2)]
        calls += 1
        return value

    # Change only the standard-library wall clock; the fixture must
    # still wait its requested duration before reporting missing logs.
    monkeypatch.setattr(time, "time", discontinuous_wall_time)
    started = time.monotonic()
    lines = wait_for_access_log(str(tmp_path), timeout=0.08, interval=0.01)
    elapsed = time.monotonic() - started
    assert lines == []
    assert 0.08 <= elapsed < 1.0


class TestWriteConfigHelper:
    """Tests for the write_config helper function."""

    def test_rotate_daily_true_in_output(self, test_env: AccessLogTestEnv) -> None:
        """
        write_config with rotate_daily=True should produce YAML with rotate_daily: true.
        """
        config_path = write_config(
            test_env.temp_dir,
            test_env.proxy_port,
            path_prefix="logs/rotate_test",
            rotate_daily=True,
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "rotate_daily: true" in content, (
            f"Expected 'rotate_daily: true' in config, got:\n{content}"
        )

    def test_rotate_daily_false_in_output(self, test_env: AccessLogTestEnv) -> None:
        """
        write_config with rotate_daily=False should produce YAML with rotate_daily:
        false.
        """
        config_path = write_config(
            test_env.temp_dir,
            test_env.proxy_port,
            path_prefix="logs/rotate_test",
            rotate_daily=False,
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "rotate_daily: false" in content, (
            f"Expected 'rotate_daily: false' in config, got:\n{content}"
        )

    def test_rotate_daily_default_omitted(self, test_env: AccessLogTestEnv) -> None:
        """write_config without rotate_daily should omit the key from writer config."""
        config_path = write_config(
            test_env.temp_dir,
            test_env.proxy_port,
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "rotate_daily" not in content, (
            f"rotate_daily should be omitted when not specified, got:\n{content}"
        )

    def test_log_format_default_omitted(self, test_env: AccessLogTestEnv) -> None:
        """write_config with default log_format='text' should omit format key from YAML.

        This matches the pattern in conf/example.yaml where the default
        writer omits the format key, letting the Rust default apply.
        """
        config_path = write_config(
            test_env.temp_dir,
            test_env.proxy_port,
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "format" not in content, (
            "format key should be omitted when log_format='text' (default),"
            + f" got:\n{content}"
        )

    def test_log_format_json_in_output(self, test_env: AccessLogTestEnv) -> None:
        """write_config with log_format='json' should produce YAML with format: json."""
        config_path = write_config(
            test_env.temp_dir,
            test_env.proxy_port,
            path_prefix="logs/json_test",
            log_format="json",
        )
        with open(config_path, "r") as f:
            content = f.read()
        config = TypeAdapter(ConfigDict).validate_python(yaml.safe_load(content))
        plugins = config["plugins"]
        assert isinstance(plugins, dict)
        access_log = plugins["access_log"]
        assert isinstance(access_log, dict)
        writers = access_log["writers"]
        assert isinstance(writers, list) and len(writers) == 1
        writer = writers[0]
        assert isinstance(writer, dict)
        assert writer["format"] == "json"
