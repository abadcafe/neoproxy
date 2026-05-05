"""
Black-box tests for access log functionality.

Tests verify that neoproxy produces correct access log files
when processing proxy requests.

The access_log.file layer writes to logs/access.log (hardcoded path,
text format). The layer is configured per-service.
"""

import os
import re
import subprocess
import time
import socket
import tempfile
import shutil
from typing import Generator

import pytest

from .utils.helpers import (
    NEOPROXY_BINARY,
    curl_request,
    terminate_process,
    wait_for_proxy,
)


# ==============================================================================
# Helper: Write config YAML (new format)
# ==============================================================================


def write_config(
    config_dir: str,
    proxy_port: int,
    context_fields: list[str] | None = None,
    include_layer: bool = True,
) -> str:
    """
    Write a neoproxy config file with access log layer.

    Args:
        config_dir: Directory to write config
        proxy_port: Port for the HTTP proxy listener
        context_fields: Optional list of context fields for the layer
        include_layer: Whether to include access_log.file layer on service

    Returns:
        Path to the config file
    """
    log_dir = os.path.join(config_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    layers = []
    if include_layer:
        layer_args: dict = {}
        if context_fields:
            layer_args["context_fields"] = context_fields
        layers.append({"kind": "access_log.file", "args": layer_args})

    config = {
        "listeners": [
            {"name": "http_main", "kind": "http", "addresses": [f"127.0.0.1:{proxy_port}"]}
        ],
        "servers": [
            {
                "name": "http_proxy",
                "hostnames": [],
                "listeners": ["http_main"],
                "service": "echo_svc",
            }
        ],
        "services": [
            {
                "name": "echo_svc",
                "kind": "echo.echo",
                "layers": layers,
            }
        ],
    }

    config_path = os.path.join(config_dir, "server.yaml")
    from .conftest import _dict_to_yaml
    with open(config_path, "w") as f:
        f.write(_dict_to_yaml(config))

    return config_path


def start_proxy_with_cwd(config_path: str, cwd: str) -> subprocess.Popen:
    """Start proxy with a specific working directory.

    The access log writer uses a hardcoded relative path (logs/access.log),
    so the proxy's CWD must be set to the test's temp directory.
    """
    binary_path = os.path.abspath(NEOPROXY_BINARY)
    return subprocess.Popen(
        [binary_path, "--config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
    )


def find_access_log_files(log_dir: str, prefix: str = "access.log") -> list[str]:
    """
    Find access log files matching the given prefix in the log directory.

    Args:
        log_dir: Directory to search
        prefix: File name prefix to match

    Returns:
        List of matching file paths, sorted
    """
    if not os.path.exists(log_dir):
        return []
    files = []
    for f in os.listdir(log_dir):
        if f.startswith(prefix):
            files.append(os.path.join(log_dir, f))
    return sorted(files)


def read_access_log_lines(log_dir: str, prefix: str = "access.log") -> list[str]:
    """
    Read all lines from access log files matching the prefix.

    Args:
        log_dir: Directory to search
        prefix: File name prefix

    Returns:
        List of non-empty lines from all matching files
    """
    lines: list[str] = []
    for path in find_access_log_files(log_dir, prefix):
        with open(path, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
    return lines


def wait_for_access_log(
    log_dir: str,
    min_lines: int = 1,
    timeout: float = 5.0,
    interval: float = 0.5,
    prefix: str = "access.log",
) -> list[str]:
    """
    Wait for access log files to appear with minimum number of lines.

    This function polls the log directory until the expected number of
    log lines appear or the timeout expires.

    Args:
        log_dir: Directory to search for log files
        min_lines: Minimum number of log lines to wait for
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds
        prefix: Log file name prefix

    Returns:
        List of log lines (may be empty if timeout)
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        lines = read_access_log_lines(log_dir, prefix)
        if len(lines) >= min_lines:
            return lines
        time.sleep(interval)
    return read_access_log_lines(log_dir, prefix)


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def test_env() -> Generator[dict, None, None]:
    """
    Provide a test environment with temp dir and unique port.
    """
    from .conftest import get_unique_port

    temp_dir = tempfile.mkdtemp(prefix="neoproxy_accesslog_test_")
    proxy_port = get_unique_port()
    log_dir = os.path.join(temp_dir, "logs")

    yield {
        "temp_dir": temp_dir,
        "proxy_port": proxy_port,
        "log_dir": log_dir,
    }

    shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Tests: Access Log File Creation and Text Format
# ==============================================================================


class TestAccessLogTextFormat:
    """Tests for access log in text format (default, only supported format)."""

    def test_access_log_file_created_after_request(
        self, test_env: dict
    ) -> None:
        """Access log file should be created after processing a request."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
        )
        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Access log should have at least one line"

    def test_access_log_text_format_fields(
        self, test_env: dict
    ) -> None:
        """Text format log line should contain all required fields.

        Expected format:
        [YYYY-MM-DD HH:MM:SS] CLIENT_IP:CLIENT_PORT -> SERVER_IP:SERVER_PORT METHOD TARGET STATUS DURATIONms svc=SERVICE
        """
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
        )
        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"

        line = lines[0]
        # Verify text format structure:
        # [YYYY-MM-DD HH:MM:SS] IP:PORT -> IP:PORT METHOD TARGET STATUS DURATIONms svc=NAME
        assert re.search(r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]", line), \
            f"Should contain timestamp in brackets, got: {line}"
        assert re.search(r"\d+\.\d+\.\d+\.\d+:\d+", line), \
            f"Should contain client IP:port, got: {line}"
        assert "GET" in line, \
            f"Should contain GET method, got: {line}"
        assert re.search(r"\d{3}", line), \
            f"Should contain status code, got: {line}"
        assert re.search(r"\d+ms", line), \
            f"Should contain duration in ms, got: {line}"

    def test_access_log_text_service_name(
        self, test_env: dict
    ) -> None:
        """Text format should include svc=<name> field."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
        )
        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"
        assert "svc=echo_svc" in lines[0], \
            f"Should contain service name, got: {lines[0]}"


# ==============================================================================
# Tests: Graceful Shutdown Flush
# ==============================================================================


class TestAccessLogGracefulShutdown:
    """Tests for access log flush on graceful shutdown."""

    def test_logs_flushed_on_shutdown(
        self, test_env: dict
    ) -> None:
        """Access log buffer should be flushed when proxy shuts down."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
        )
        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200

            # Don't wait for flush interval - just shut down
            time.sleep(0.5)
        finally:
            terminate_process(proc)

        # After shutdown, logs should have been flushed
        time.sleep(0.5)
        lines = read_access_log_lines(test_env["log_dir"])
        assert len(lines) >= 1, \
            "Logs should be flushed on graceful shutdown"


# ==============================================================================
# Tests: Context Fields
# ==============================================================================


class TestAccessLogContextFields:
    """Tests for context_fields in access log output."""

    def test_access_log_with_layer_works(
        self, test_env: dict
    ) -> None:
        """Access log with context_fields should still create log entries."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            context_fields=["echo.echo"],
        )
        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"

        line = lines[0]
        # Verify basic log content is present
        assert "GET" in line, f"Should contain GET method, got: {line}"
        assert "200" in line, f"Should contain status 200, got: {line}"
        assert "svc=echo_svc" in line, f"Should contain service name, got: {line}"


# ==============================================================================
# Tests: Log Content Validation
# ==============================================================================


class TestAccessLogContent:
    """Tests for validating access log content."""

    def test_log_contains_request_details(
        self, test_env: dict
    ) -> None:
        """Access log should contain request method, target, and status."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
        )
        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"

        line = lines[0]
        # Verify log contains request details
        assert "GET" in line, f"Should contain method, got: {line}"
        assert "200" in line, f"Should contain status, got: {line}"
        assert "ms" in line, f"Should contain duration, got: {line}"
        assert "svc=echo_svc" in line, f"Should contain service name, got: {line}"


# ==============================================================================
# Tests: Without Access Log Layer
# ==============================================================================


class TestAccessLogDisabled:
    """Tests for behavior when access_log layer is not configured."""

    def test_no_log_file_without_layer(
        self, test_env: dict
    ) -> None:
        """Without access_log.file layer, no access log should be created."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            include_layer=False,
        )
        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        # No access log files should be created
        time.sleep(1)
        lines = read_access_log_lines(test_env["log_dir"])
        assert len(lines) == 0, \
            "Without access_log layer, no log lines should be produced"
