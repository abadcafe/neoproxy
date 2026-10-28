"""access log scenario fixture interface.
Tests: process and protocol consumers.
"""

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Generator
from dataclasses import dataclass

import pytest

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import ConfigDict, JsonValue, dict_to_yaml
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port


@dataclass(frozen=True)
class AccessLogTestEnv:
    temp_dir: str
    proxy_port: int
    log_dir: str


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

    layers: list[JsonValue] = []
    if include_layer:
        layer_args: ConfigDict = {"writer": path_prefix}
        if context_fields:
            layer_args["context_fields"] = [field for field in context_fields]
        layers.append({"kind": "access_log.file", **layer_args})

    config: ConfigDict = {
        "listeners": [
            {
                "name": "http_main",
                "kind": "http",
                "addresses": [f"127.0.0.1:{proxy_port}"],
            }
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

    plugins: ConfigDict = {"echo": None}
    if include_layer:
        writer_config: ConfigDict = {"path_prefix": path_prefix}
        if log_format != "text":
            writer_config["format"] = log_format
        if rotate_daily is not None:
            writer_config["rotate_daily"] = rotate_daily
        plugins["access_log"] = {"writers": [writer_config]}
    config["plugins"] = plugins

    config_path = os.path.join(config_dir, "server.yaml")
    with open(config_path, "w") as f:
        _ = f.write(dict_to_yaml(config))

    return config_path


def start_proxy_with_cwd(config_path: str, cwd: str) -> ProxyProcess:
    """Start proxy with a specific working directory.

    The access log writer uses a configurable relative path (logs/access),
    so the proxy's CWD must be set to the test's temp directory.
    """
    binary_path = os.path.abspath(NEOPROXY_BINARY)
    return ProxyProcess(
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
    files: list[str] = []
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
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        lines = read_access_log_lines(log_dir, prefix)
        if len(lines) >= min_lines:
            return lines
        time.sleep(interval)
    return read_access_log_lines(log_dir, prefix)


@pytest.fixture
def test_env() -> Generator[AccessLogTestEnv, None, None]:
    """
    Provide a test environment with temp dir and unique port.
    """

    temp_dir = tempfile.mkdtemp(prefix="neoproxy_accesslog_test_")
    proxy_port = get_unique_port()
    log_dir = os.path.join(temp_dir, "logs")

    yield AccessLogTestEnv(temp_dir=temp_dir, proxy_port=proxy_port, log_dir=log_dir)

    shutil.rmtree(temp_dir, ignore_errors=True)
