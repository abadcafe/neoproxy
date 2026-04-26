"""
Black-box tests for access log functionality.

Tests verify that neoproxy produces correct access log files
when processing proxy requests.
"""

import os
import re
import json
import time
import socket
import tempfile
import shutil
from typing import Optional, Generator

import pytest
import yaml  # pyyaml - standard in test environments

from .utils.helpers import (
    start_proxy,
    terminate_process,
    wait_for_proxy,
)


# ==============================================================================
# Helper: Write config YAML
# ==============================================================================


def write_config(
    config_dir: str,
    proxy_port: int,
    access_log_config: Optional[dict] = None,
    server_access_log_config: Optional[dict] = None,
) -> str:
    """
    Write a neoproxy config file with access log settings.

    Args:
        config_dir: Directory to write config and logs
        proxy_port: Port for the HTTP proxy listener
        access_log_config: Top-level access_log config (optional)
        server_access_log_config: Server-level access_log override (optional)

    Returns:
        Path to the config file
    """
    log_dir = os.path.join(config_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    config = {
        "worker_threads": 1,
        "log_directory": log_dir,
        "services": [
            {
                "name": "tunnel",
                "kind": "connect_tcp.connect_tcp",
            }
        ],
        "servers": [
            {
                "name": "http_proxy",
                "service": "tunnel",
                "listeners": [
                    {
                        "kind": "http",
                        "args": {
                            "addresses": [f"127.0.0.1:{proxy_port}"],
                        },
                    }
                ],
            }
        ],
    }

    if access_log_config is not None:
        config["access_log"] = access_log_config

    if server_access_log_config is not None:
        config["servers"][0]["access_log"] = server_access_log_config

    config_path = os.path.join(config_dir, "server.yaml")
    with open(config_path, "w") as f:
        yaml.dump(config, f)

    return config_path


def send_connect_request(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
) -> int:
    """
    Send an HTTP CONNECT request to the proxy and return the status code.

    Args:
        proxy_host: Proxy host
        proxy_port: Proxy port
        target_host: Target host for CONNECT
        target_port: Target port for CONNECT

    Returns:
        HTTP status code from the proxy response

    Raises:
        RuntimeError: If connection fails, response is empty, or response is malformed
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        try:
            sock.connect((proxy_host, proxy_port))
        except socket.error as e:
            raise RuntimeError(
                f"Failed to connect to proxy at {proxy_host}:{proxy_port}: {e}"
            )

        request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode())

        try:
            response = sock.recv(4096).decode()
        except UnicodeDecodeError as e:
            raise RuntimeError(
                f"Invalid UTF-8 response from proxy at {proxy_host}:{proxy_port}: {e}"
            )
        if not response:
            raise RuntimeError(
                f"Empty response from proxy at {proxy_host}:{proxy_port}"
            )

        # Parse status code from "HTTP/1.1 200 OK\r\n..."
        lines = response.split("\r\n")
        if not lines:
            raise RuntimeError(
                f"Malformed response from proxy (no CRLF): {response!r}"
            )

        status_line = lines[0]
        parts = status_line.split(" ")
        if len(parts) < 2:
            raise RuntimeError(
                f"Malformed status line from proxy: {status_line!r}"
            )

        try:
            status_code = int(parts[1])
        except ValueError:
            raise RuntimeError(
                f"Invalid status code in response: {parts[1]!r}"
            )

        return status_code
    finally:
        sock.close()


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
# Tests: Text Format
# ==============================================================================


class TestAccessLogTextFormat:
    """Tests for access log in text format (default)."""

    def test_access_log_file_created_after_request(
        self, test_env: dict
    ) -> None:
        """Access log file should be created after processing a request."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={"enabled": True, "format": "text"},
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            # Send a CONNECT request (target doesn't need to exist)
            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Access log should have at least one line"

    def test_access_log_text_format_fields(
        self, test_env: dict
    ) -> None:
        """Text format log line should contain all required fields."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "text",
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"

        line = lines[0]
        # Verify text format structure:
        # IP:PORT - [TIME] "METHOD TARGET" STATUS DURATIONms key=value...
        # Example: 127.0.0.1:54321 - [25/Apr/2026:10:00:00 +0800] "CONNECT example.com:443" 200 50ms service=tunnel
        assert re.search(r"\d+\.\d+\.\d+\.\d+:\d+", line), \
            f"Should contain client IP:port, got: {line}"
        assert re.search(r"\[.+\]", line), \
            f"Should contain timestamp in brackets, got: {line}"
        assert '"CONNECT example.com:443"' in line, \
            f"Should contain request line, got: {line}"
        assert re.search(r"\d{3}", line), \
            f"Should contain status code, got: {line}"
        assert re.search(r"\d+ms", line), \
            f"Should contain duration in ms, got: {line}"

    def test_access_log_text_service_name(
        self, test_env: dict
    ) -> None:
        """Text format should include service=<name> field."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "text",
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"
        assert "service=tunnel" in lines[0], \
            f"Should contain service name, got: {lines[0]}"


# ==============================================================================
# Tests: JSON Format
# ==============================================================================


class TestAccessLogJsonFormat:
    """Tests for access log in JSON format."""

    def test_access_log_json_format_valid(
        self, test_env: dict
    ) -> None:
        """JSON format log line should be valid JSON with required fields."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "json",
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"

        entry = json.loads(lines[0])
        assert "time" in entry, "JSON should have 'time' field"
        assert "client_ip" in entry, "JSON should have 'client_ip' field"
        assert "client_port" in entry, "JSON should have 'client_port' field"
        assert "method" in entry, "JSON should have 'method' field"
        assert "target" in entry, "JSON should have 'target' field"
        assert "status" in entry, "JSON should have 'status' field"
        assert "duration_ms" in entry, "JSON should have 'duration_ms' field"
        assert "service" in entry, "JSON should have 'service' field"

        assert entry["method"] == "CONNECT"
        assert entry["target"] == "example.com:443"
        assert entry["service"] == "tunnel"
        assert isinstance(entry["status"], int)
        assert isinstance(entry["duration_ms"], int)
        assert isinstance(entry["client_port"], int)

    def test_access_log_json_time_format_iso8601(
        self, test_env: dict
    ) -> None:
        """JSON format time field should be ISO8601."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "json",
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
        assert len(lines) >= 1, "Should have at least one log line"

        entry = json.loads(lines[0])
        # ISO8601 format: 2026-04-25T10:00:00[.nanoseconds]+08:00
        assert re.match(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{2}:\d{2}",
            entry["time"],
        ), f"Time should be ISO8601, got: {entry['time']}"


# ==============================================================================
# Tests: Config Override
# ==============================================================================


class TestAccessLogConfigOverride:
    """Tests for server-level config overriding top-level config."""

    def test_server_level_overrides_path_prefix(
        self, test_env: dict
    ) -> None:
        """Server-level path_prefix should override top-level."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "text",
                "path_prefix": "default_access.log",
            },
            server_access_log_config={
                "path_prefix": "http_access.log",
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        # Wait for access log with custom prefix
        lines = wait_for_access_log(
            test_env["log_dir"], min_lines=1, timeout=5.0, prefix="http_access.log"
        )

        # Should use server-level prefix, not top-level
        http_files = find_access_log_files(
            test_env["log_dir"], "http_access.log"
        )
        default_files = find_access_log_files(
            test_env["log_dir"], "default_access.log"
        )
        assert len(http_files) > 0, \
            "Should create file with server-level prefix"
        assert len(default_files) == 0, \
            "Should NOT create file with top-level prefix"

    def test_server_level_disabled_overrides_enabled(
        self, test_env: dict
    ) -> None:
        """Server-level enabled=false should disable access log for that server."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "text",
            },
            server_access_log_config={
                "enabled": False,
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )
        finally:
            terminate_process(proc)

        # No access log files should be created even after shutdown
        lines = read_access_log_lines(test_env["log_dir"])
        assert len(lines) == 0, \
            "Disabled access log should produce no log lines"


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
            access_log_config={
                "enabled": True,
                "format": "text",
                "buffer": "1MiB",
                "flush": "60s",  # Long flush interval
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            send_connect_request(
                "127.0.0.1",
                test_env["proxy_port"],
                "example.com",
                443,
            )

            # Don't wait for flush interval - just shut down
            time.sleep(0.5)
        finally:
            terminate_process(proc)

        # After shutdown, logs should have been flushed
        time.sleep(0.5)
        lines = read_access_log_lines(test_env["log_dir"])
        assert len(lines) >= 1, \
            "Logs should be flushed on graceful shutdown even with long flush interval"


# ==============================================================================
# Tests: File Rotation by Size
# ==============================================================================


class TestAccessLogFileRotation:
    """Tests for access log file rotation by max_size."""

    def test_file_rotation_creates_dated_files(
        self, test_env: dict
    ) -> None:
        """Access log files should use dated naming convention."""
        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "text",
            },
        )
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

            # Start a local target server so CONNECT requests succeed quickly
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            target_sock.bind(("127.0.0.1", 0))
            target_sock.listen(5)
            target_port = target_sock.getsockname()[1]

            try:
                # Send a request to generate log data
                send_connect_request(
                    "127.0.0.1",
                    test_env["proxy_port"],
                    "127.0.0.1",
                    target_port,
                )
            finally:
                target_sock.close()
        finally:
            terminate_process(proc)

        # After shutdown, logs should be flushed
        time.sleep(0.5)  # Give a moment for file system to sync

        # Verify access log files were created with dated naming
        files = find_access_log_files(test_env["log_dir"])
        assert len(files) >= 1, \
            f"Should have at least one log file, got {len(files)}"

        # Verify file naming scheme: access.log.YYYY-MM-DD[.N]
        for f in files:
            basename = os.path.basename(f)
            assert basename.startswith("access.log."), \
                f"File should start with 'access.log.', got: {basename}"
            # Verify date portion exists (YYYY-MM-DD)
            parts = basename.split(".")
            assert len(parts) >= 3, \
                f"File should have format access.log.YYYY-MM-DD[.N], got: {basename}"


# ==============================================================================
# Tests: Service Metrics in Log Output
# ==============================================================================


class TestAccessLogServiceMetrics:
    """Tests for service metrics appearing in access log output."""

    def test_text_format_contains_service_metrics(
        self, test_env: dict
    ) -> None:
        """Text format should include service.connect_ms metric."""
        # Start a real target server so connect_tcp succeeds
        # and produces connect_ms metric
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        target_sock.bind(("127.0.0.1", 0))
        target_sock.listen(5)
        target_port = target_sock.getsockname()[1]

        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "text",
            },
        )
        try:
            proc = start_proxy(config_path)
            try:
                assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

                # CONNECT to the real target so connect_tcp measures connect_ms
                send_connect_request(
                    "127.0.0.1",
                    test_env["proxy_port"],
                    "127.0.0.1",
                    target_port,
                )
            finally:
                terminate_process(proc)

            # After shutdown, logs should be flushed
            lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
            assert len(lines) >= 1, "Should have at least one log line"

            line = lines[0]
            assert "service.connect_ms=" in line, \
                f"Text log should contain service.connect_ms metric, got: {line}"
        finally:
            target_sock.close()

    def test_json_format_contains_service_metrics(
        self, test_env: dict
    ) -> None:
        """JSON format should include service.connect_ms metric."""
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        target_sock.bind(("127.0.0.1", 0))
        target_sock.listen(5)
        target_port = target_sock.getsockname()[1]

        config_path = write_config(
            test_env["temp_dir"],
            test_env["proxy_port"],
            access_log_config={
                "enabled": True,
                "format": "json",
            },
        )
        try:
            proc = start_proxy(config_path)
            try:
                assert wait_for_proxy("127.0.0.1", test_env["proxy_port"])

                send_connect_request(
                    "127.0.0.1",
                    test_env["proxy_port"],
                    "127.0.0.1",
                    target_port,
                )
            finally:
                terminate_process(proc)

            # After shutdown, logs should be flushed
            lines = wait_for_access_log(test_env["log_dir"], min_lines=1, timeout=5.0)
            assert len(lines) >= 1, "Should have at least one log line"

            entry = json.loads(lines[0])
            assert "service.connect_ms" in entry, \
                f"JSON log should contain service.connect_ms, got keys: {list(entry.keys())}"
        finally:
            target_sock.close()
