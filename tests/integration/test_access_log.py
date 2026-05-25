"""
Black-box tests for access log functionality.

Tests verify that neoproxy produces correct access log files
when processing proxy requests.

The access_log.file layer writes to logs/access.{date} (configurable
path_prefix with date suffix when rotate_daily is true), text format
by default. The layer is configured per-service.
"""

import base64
import json
import os
import re
import subprocess
import time
import tempfile
import shutil
from typing import Generator

import pytest

from .conftest import _dict_to_yaml, get_unique_port

from .utils.helpers import (
    NEOPROXY_BINARY,
    curl_request,
    terminate_process,
    wait_for_process_exit,
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
    path_prefix: str = "logs/access",
    log_format: str = "text",
    rotate_daily: bool | None = None,
) -> str:
    """
    Write a neoproxy config file with access log layer.

    Args:
        config_dir: Directory to write config
        proxy_port: Port for the HTTP proxy listener
        context_fields: Optional list of context fields for the layer
        include_layer: Whether to include access_log.file layer on service
        path_prefix: Writer path prefix (default: logs/access)
        log_format: Log format - "text" or "json" (default: text)
        rotate_daily: Whether to rotate log at date boundary. None = omit
            (let Rust default apply), True/False = explicit value.

    Returns:
        Path to the config file
    """
    log_dir = os.path.join(config_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    layers = []
    if include_layer:
        layer_args: dict = {"writer": path_prefix}
        if context_fields:
            layer_args["context_fields"] = context_fields
        layers.append({"kind": "access_log.file", "args": layer_args})

    config: dict = {
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

    plugins: dict = {"echo": None}
    if include_layer:
        writer_config: dict = {"path_prefix": path_prefix}
        if log_format != "text":
            writer_config["format"] = log_format
        if rotate_daily is not None:
            writer_config["rotate_daily"] = rotate_daily
        plugins["access_log"] = {"writers": [writer_config]}
    config["plugins"] = plugins

    config_path = os.path.join(config_dir, "server.yaml")
    with open(config_path, "w") as f:
        f.write(_dict_to_yaml(config))

    return config_path


def start_proxy_with_cwd(config_path: str, cwd: str) -> subprocess.Popen:
    """Start proxy with a specific working directory.

    The access log writer uses a configurable relative path (logs/access),
    so the proxy's CWD must be set to the test's temp directory.
    """
    binary_path = os.path.abspath(NEOPROXY_BINARY)
    return subprocess.Popen(
        [binary_path, "--config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
    )


def find_access_log_files(log_dir: str, prefix: str = "access") -> list[str]:
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


def read_access_log_lines(log_dir: str, prefix: str = "access") -> list[str]:
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
    prefix: str = "access",
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
    """Tests for access log in text format (default format)."""

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
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=2.0)
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

        # No access log files should be created (proxy already terminated,
        # no more log entries can appear)
        lines = read_access_log_lines(test_env["log_dir"])
        assert len(lines) == 0, \
            "Without access_log layer, no log lines should be produced"


# ==============================================================================
# Tests: Named Access Log Writers
# ==============================================================================


class TestAccessLogNamedWriters:
    """Tests for named access log writers (plugin config)."""

    def test_writer_with_custom_path_prefix(
        self, test_env: dict
    ) -> None:
        """Access log writer with custom path_prefix writes to that path."""

        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            path_prefix="logs/custom_access",
        )

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0, prefix="custom_access"
        )
        assert len(lines) >= 1, "Access log should be written to custom path_prefix"

    def test_multiple_writers_different_paths(
        self, test_env: dict
    ) -> None:
        """Multiple named writers write to different files."""

        port2 = get_unique_port()

        config = {
            "plugins": {
                "echo": None,
                "access_log": {
                    "writers": [
                        {"path_prefix": "logs/default_access"},
                        {"path_prefix": "logs/audit"},
                    ]
                }
            },
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": [f"127.0.0.1:{test_env['proxy_port']}"]},
                {"name": "http_alt", "kind": "http", "addresses": [f"127.0.0.1:{port2}"]},
            ],
            "servers": [
                {
                    "name": "server_default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                },
                {
                    "name": "server_audit",
                    "hostnames": [],
                    "listeners": ["http_alt"],
                    "service": "audit_svc",
                },
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {"kind": "access_log.file", "args": {"writer": "logs/default_access"}}
                    ],
                },
                {
                    "name": "audit_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {"kind": "access_log.file", "args": {"writer": "logs/audit"}}
                    ],
                },
            ],
        }

        config_path = os.path.join(test_env["temp_dir"], "server.yaml")
        with open(config_path, "w") as f:
            f.write(_dict_to_yaml(config))

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])
            assert wait_for_proxy("127.0.0.1", port2)

            status1 = curl_request("http://example.com/", test_env["proxy_port"])
            assert status1 == 200

            status2 = curl_request("http://example.com/", port2)
            assert status2 == 200
        finally:
            terminate_process(proc)

        default_lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0, prefix="default_access"
        )
        audit_lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0, prefix="audit"
        )
        assert len(default_lines) >= 1, "Default writer should have log entries"
        assert len(audit_lines) >= 1, "Audit writer should have log entries"

    def test_writer_unknown_path_prefix_fails_to_build(
        self, test_env: dict
    ) -> None:
        """Layer referencing unknown writer path_prefix should fail."""

        config = {
            "plugins": {
                "echo": None,
                "access_log": {
                    "writers": [
                        {"path_prefix": "logs/real_writer"},
                    ]
                }
            },
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": [f"127.0.0.1:{test_env['proxy_port']}"]}
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
                    "layers": [
                        {"kind": "access_log.file", "args": {"writer": "logs/nonexistent"}}
                    ],
                }
            ],
        }

        config_path = os.path.join(test_env["temp_dir"], "server.yaml")
        with open(config_path, "w") as f:
            f.write(_dict_to_yaml(config))

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            # Proxy should fail to start or exit with error because
            # the writer reference is invalid
            exit_code, _ = wait_for_process_exit(proc, timeout=5.0)
            assert exit_code != 0, "Proxy should exit with error for unknown writer path_prefix"
        finally:
            terminate_process(proc)

    def test_writer_with_json_format(
        self, test_env: dict
    ) -> None:
        """Writer with format=json should produce JSON log lines."""

        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            path_prefix="logs/json_access",
            log_format="json",
        )

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0, prefix="json_access"
        )
        assert len(lines) >= 1, "JSON format writer should produce log entries"
        # Verify the line is valid JSON
        parsed = json.loads(lines[0])
        assert "status" in parsed, "JSON log entry should have status field"
        assert "method" in parsed, "JSON log entry should have method field"

    def test_writer_missing_field_fails_to_build(
        self, test_env: dict
    ) -> None:
        """Layer with missing writer field should fail to start.

        Per spec: 'Missing writer field in layer args -> build error'.
        The writer field is required with no default, so the proxy
        should exit when it is absent.

        We pass args as a valid mapping (with context_fields but no
        writer) rather than an empty dict, because _dict_to_yaml
        renders {} as a bare "args:" key (null in YAML), which
        causes a different deserialization error than missing writer.
        """

        config = {
            "plugins": {
                "echo": None,
                "access_log": {
                    "writers": [
                        {"path_prefix": "logs/default"},
                    ]
                }
            },
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": [f"127.0.0.1:{test_env['proxy_port']}"]}
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
                    "layers": [
                        # Missing 'writer' field - should cause build error.
                        # Use context_fields to ensure args is a valid mapping
                        # (not rendered as null by _dict_to_yaml).
                        {"kind": "access_log.file", "args": {"context_fields": []}}
                    ],
                }
            ],
        }

        config_path = os.path.join(test_env["temp_dir"], "server.yaml")
        with open(config_path, "w") as f:
            f.write(_dict_to_yaml(config))

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            exit_code, _ = wait_for_process_exit(proc, timeout=5.0)
            assert exit_code != 0, "Proxy should exit with error for missing writer field"
        finally:
            terminate_process(proc)

    def test_writer_rotate_daily_false_no_date_suffix(
        self, test_env: dict
    ) -> None:
        """Writer with rotate_daily=false writes to path_prefix without date suffix.

        Per spec: 'The actual log file is {path_prefix}.{date} when
        rotate_daily is enabled, or {path_prefix} when rotate_daily
        is false.' This test verifies the no-date-suffix behavior.
        """

        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            path_prefix="logs/no_rotate",
            rotate_daily=False,
        )

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0, prefix="no_rotate"
        )
        assert len(lines) >= 1, "Access log should be written to path_prefix without date suffix"

        # Verify no date-suffixed file exists when rotate_daily=false
        log_files = find_access_log_files(test_env["log_dir"], prefix="no_rotate")
        assert len(log_files) >= 1, "Log file should exist"
        for f in log_files:
            basename = os.path.basename(f)
            # Should NOT match pattern like "no_rotate.2026-05-09"
            assert not re.match(r"no_rotate\.\d{4}-\d{2}-\d{2}", basename), \
                f"File {basename} should not have date suffix when rotate_daily=false"

    def test_writer_rotate_daily_true_has_date_suffix(
        self, test_env: dict
    ) -> None:
        """Writer with rotate_daily=true (default) produces date-suffixed filenames.

        Per spec: 'The actual log file is {path_prefix}.{date} when
        rotate_daily is enabled.' This test verifies the date suffix
        is present in the default (rotate_daily=true) case, ensuring
        the file naming contract for the most common rotation behavior
        is validated.
        """

        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            path_prefix="logs/daily_rotate",
            rotate_daily=True,
        )

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            status = curl_request("http://example.com/", test_env["proxy_port"])
            assert status == 200
        finally:
            terminate_process(proc)

        lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0, prefix="daily_rotate"
        )
        assert len(lines) >= 1, "Access log should be written with date suffix"

        # Verify date-suffixed file exists when rotate_daily=true
        log_files = find_access_log_files(test_env["log_dir"], prefix="daily_rotate")
        assert len(log_files) >= 1, "Log file should exist"
        found_date_suffix = False
        for f in log_files:
            basename = os.path.basename(f)
            if re.match(r"daily_rotate\.\d{4}-\d{2}-\d{2}", basename):
                found_date_suffix = True
                break
        assert found_date_suffix, \
            f"At least one log file should have date suffix (daily_rotate.YYYY-MM-DD), got: {[os.path.basename(f) for f in log_files]}"


# ==============================================================================
# Tests: Context Field Values in Log Output
# ==============================================================================


class TestAccessLogContextFieldValues:
    """Tests verifying that context field values actually appear in log output.

    CR-003: Previous tests configured context_fields but only checked for
    generic fields (GET, 200, svc=echo_svc). These tests verify that
    context field key=value pairs from other layers (e.g., basic_auth.user)
    actually appear in the written log lines.
    """

    def test_text_log_contains_auth_context_field(
        self, test_env: dict
    ) -> None:
        """Auth context field should appear in text format log output.

        Configures auth.basic_auth layer before access_log.file layer with
        context_fields=["basic_auth.user"]. After authenticating with
        valid credentials, the log should contain the full key=value pair
        "basic_auth.user=admin".
        """
        port = test_env["proxy_port"]

        config: dict = {
            "plugins": {
                "echo": None,
                "auth": None,
                "access_log": {
                    "writers": [
                        {"path_prefix": "logs/access"},
                    ]
                }
            },
            "listeners": [
                {"name": "http_main", "kind": "http",
                 "addresses": [f"127.0.0.1:{port}"]},
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
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": {
                                "writer": "logs/access",
                                "context_fields": ["basic_auth.user"],
                            },
                        },
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {"username": "admin", "password": "secret"},
                                ],
                            },
                        },
                    ],
                }
            ],
        }

        config_path = os.path.join(test_env["temp_dir"], "server.yaml")
        with open(config_path, "w") as f:
            f.write(_dict_to_yaml(config))

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", port)

            # Send request WITHOUT auth - should get 407
            status = curl_request("http://example.com/", port)
            assert status == 407

            # Send request WITH valid auth - should get 200
            creds = base64.b64encode(b"admin:secret").decode()
            status = curl_request(
                "http://example.com/", port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 200
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"

        # The authenticated request's log line should contain the full
        # context field key=value pair (CR-002 fix: full key preserved,
        # not stripped to "basic_auth.user")
        auth_lines = [line for line in lines if "basic_auth.user=admin" in line]
        assert len(auth_lines) >= 1, \
            f"Log should contain 'basic_auth.user=admin', got: {lines}"

    def test_json_log_extensions_nested_under_extensions_key(
        self, test_env: dict
    ) -> None:
        """JSON format should nest context field extensions under "extensions" key.

        CR-004: Verifies the CR-001 fix end-to-end. When a JSON writer is
        configured with context_fields, the parsed JSON output should have
        extensions under a dedicated "extensions" object, not at the top
        level where they could silently overwrite built-in keys.
        """
        port = test_env["proxy_port"]

        config: dict = {
            "plugins": {
                "echo": None,
                "auth": None,
                "access_log": {
                    "writers": [
                        {"path_prefix": "logs/json_access", "format": "json"},
                    ]
                }
            },
            "listeners": [
                {"name": "http_main", "kind": "http",
                 "addresses": [f"127.0.0.1:{port}"]},
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
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": {
                                "writer": "logs/json_access",
                                "context_fields": [
                                    "basic_auth.user",
                                    "basic_auth.auth_type",
                                ],
                            },
                        },
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {"username": "admin", "password": "secret"},
                                ],
                            },
                        },
                    ],
                }
            ],
        }

        config_path = os.path.join(test_env["temp_dir"], "server.yaml")
        with open(config_path, "w") as f:
            f.write(_dict_to_yaml(config))

        proc = start_proxy_with_cwd(config_path, test_env["temp_dir"])
        try:
            assert wait_for_proxy("127.0.0.1", port)

            # Authenticate with valid credentials
            creds = base64.b64encode(b"admin:secret").decode()
            status = curl_request(
                "http://example.com/", port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 200
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0,
            prefix="json_access",
        )
        assert len(lines) >= 1, "JSON format writer should produce log entries"

        # Find the line corresponding to the authenticated request
        # (status 200, not 407)
        found_extension = False
        for line in lines:
            parsed = json.loads(line)
            if parsed.get("status") == 200 and "extensions" in parsed:
                # CR-001 fix: extensions must be nested under "extensions" key
                ext = parsed["extensions"]
                assert "basic_auth.user" in ext, \
                    f"Extension 'basic_auth.user' should be under 'extensions', got: {ext}"
                assert ext["basic_auth.user"] == "admin", \
                    f"Extension value should be 'admin', got: {ext['basic_auth.user']}"
                assert "basic_auth.auth_type" in ext, \
                    f"Extension 'basic_auth.auth_type' should be under 'extensions', got: {ext}"
                # Built-in keys must remain at the top level
                assert parsed.get("method") == "GET", \
                    "Built-in 'method' must be at top level"
                assert isinstance(parsed.get("status"), int), \
                    "Built-in 'status' must be an integer at top level"
                # Extension keys must NOT be at the top level
                assert "basic_auth.user" not in parsed, \
                    "Extension key must not appear at top level"
                found_extension = True
                break

        assert found_extension, \
            f"No JSON log line with status 200 and 'extensions' key found. Lines: {lines}"


# ==============================================================================
# Tests: write_config Helper
# ==============================================================================


class TestWriteConfigHelper:
    """Tests for the write_config helper function."""

    def test_rotate_daily_true_in_output(self, test_env: dict) -> None:
        """write_config with rotate_daily=True should produce YAML with rotate_daily: true."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            path_prefix="logs/rotate_test",
            rotate_daily=True,
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "rotate_daily: true" in content, \
            f"Expected 'rotate_daily: true' in config, got:\n{content}"

    def test_rotate_daily_false_in_output(self, test_env: dict) -> None:
        """write_config with rotate_daily=False should produce YAML with rotate_daily: false."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            path_prefix="logs/rotate_test",
            rotate_daily=False,
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "rotate_daily: false" in content, \
            f"Expected 'rotate_daily: false' in config, got:\n{content}"

    def test_rotate_daily_default_omitted(self, test_env: dict) -> None:
        """write_config without rotate_daily should omit the key from writer config."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "rotate_daily" not in content, \
            f"rotate_daily should be omitted when not specified, got:\n{content}"

    def test_log_format_default_omitted(self, test_env: dict) -> None:
        """write_config with default log_format='text' should omit format key from YAML.

        This matches the pattern in conf/example.yaml where the default
        writer omits the format key, letting the Rust default apply.
        """
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert "format" not in content, \
            f"format key should be omitted when log_format='text' (default), got:\n{content}"

    def test_log_format_json_in_output(self, test_env: dict) -> None:
        """write_config with log_format='json' should produce YAML with format: json."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            path_prefix="logs/json_test",
            log_format="json",
        )
        with open(config_path, "r") as f:
            content = f.read()
        assert 'format: "json"' in content, \
            f"Expected 'format: \"json\"' in config, got:\n{content}"
