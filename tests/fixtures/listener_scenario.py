"""listener scenario fixture interface.
Tests: process and protocol consumers.
"""

import os
import shutil
import subprocess
import tempfile
from collections.abc import Generator

import pytest
import yaml

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, terminate_process


def write_h1_h3_config(
    config_dir: str,
    http_port: int,
    https_port: int,
    http3_port: int,
    default_port: int,
) -> str:
    """
    Write the H1/H3 consistency test configuration.

    This config uses the new listener kinds (http, https, http3) and
    server-level configuration for TLS, users, and hostnames.

    Args:
        config_dir: Directory to write config and logs
        http_port: Port for HTTP listener
        https_port: Port for HTTPS listener
        http3_port: Port for HTTP3 listener
        default_port: Port for default server listener

    Returns:
        Path to the config file
    """
    log_dir = os.path.join(config_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    config: ConfigDict = {
        "server_threads": 2,
        "plugins": {"echo": None},
        "services": [
            {
                "name": "echo",
                "kind": "echo.echo",
            }
        ],
        "listeners": [
            {
                "name": "http_main",
                "kind": "http",
                "addresses": [f"127.0.0.1:{http_port}"],
            },
            {
                "name": "https_main",
                "kind": "https",
                "addresses": [f"127.0.0.1:{https_port}"],
            },
            {
                "name": "h3_main",
                "kind": "http3",
                "addresses": [f"127.0.0.1:{http3_port}"],
                "quic_connection_max_concurrent_bidi_streams": 100,
            },
            {
                "name": "default_main",
                "kind": "http",
                "addresses": [f"127.0.0.1:{default_port}"],
            },
        ],
        "servers": [
            # Server with new http listener kind
            {
                "name": "http_server",
                "hostnames": ["http.example.com"],
                "listeners": ["http_main"],
                "service": "echo",
            },
            # Server with new https listener kind
            {
                "name": "https_server",
                "hostnames": ["https.example.com"],
                "certificates": [
                    {
                        "cert_path": "conf/certs/server.crt",
                        "key_path": "conf/certs/server.key",
                    }
                ],
                "listeners": ["https_main"],
                "service": "echo",
            },
            # Server with http3 listener (multi-address)
            {
                "name": "http3_server",
                "hostnames": ["h3.example.com"],
                "certificates": [
                    {
                        "cert_path": "conf/certs/server.crt",
                        "key_path": "conf/certs/server.key",
                    }
                ],
                "listeners": ["h3_main"],
                "service": "echo",
            },
            # Default server (no hostnames)
            {
                "name": "default_server",
                "listeners": ["default_main"],
                "service": "echo",
            },
        ],
    }

    config_path = os.path.join(config_dir, "h1_h3_consistency.yaml")
    with open(config_path, "w") as f:
        yaml.dump(config, f)

    return config_path


def write_minimal_echo_config(
    config_dir: str,
    port: int,
) -> str:
    """
    Write a minimal echo config without access_log section.

    Args:
        config_dir: Directory to write config and logs
        port: Port for the HTTP listener

    Returns:
        Path to the config file
    """
    log_dir = os.path.join(config_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    config: ConfigDict = {
        "server_threads": 1,
        "plugins": {"echo": None},
        "services": [
            {
                "name": "echo",
                "kind": "echo.echo",
            }
        ],
        "listeners": [
            {
                "name": "http_main",
                "kind": "http",
                "addresses": [f"127.0.0.1:{port}"],
            },
        ],
        "servers": [
            {
                "name": "default_server",
                "listeners": ["http_main"],
                "service": "echo",
            }
        ],
    }

    config_path = os.path.join(config_dir, "minimal_config.yaml")
    with open(config_path, "w") as f:
        yaml.dump(config, f)

    return config_path


@pytest.fixture
def h1_h3_test_env() -> Generator[tuple[str, int, int, int, int], None, None]:
    """
    Set up test environment with dynamic ports and temp directory.

    Yields:
        Tuple of (config_path, http_port, https_port, http3_port, default_port)
    """
    temp_dir = tempfile.mkdtemp(prefix="neoproxy_h1h3_test_")

    # Allocate unique ports
    http_port = get_unique_port()
    https_port = get_unique_port()
    http3_port = get_unique_port()
    default_port = get_unique_port()

    config_path = write_h1_h3_config(
        temp_dir, http_port, https_port, http3_port, default_port
    )

    yield config_path, http_port, https_port, http3_port, default_port

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def minimal_test_env() -> Generator[tuple[str, int], None, None]:
    """
    Set up minimal test environment for access log tests.

    Yields:
        Tuple of (config_path, port)
    """
    temp_dir = tempfile.mkdtemp(prefix="neoproxy_minimal_test_")
    port = get_unique_port()

    config_path = write_minimal_echo_config(temp_dir, port)

    yield config_path, port

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def proxy_with_capture(
    h1_h3_test_env: tuple[str, int, int, int, int],
) -> Generator[tuple[BytesProcess | None, bytes, str], None, None]:
    """
    Start proxy and capture stderr for error reporting.

    Yields:
        Tuple of (process, stderr_content, config_path)
    """
    config_path, _http_port, _https_port, _http3_port, _default_port = h1_h3_test_env

    proc: BytesProcess | None = None
    stderr_data = b""

    try:
        proc = ProxyProcess(
            [NEOPROXY_BINARY, "--config", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # One notification covers every worker and every listener.
        ready = proc.wait_ready()

        # If process exited or listeners not ready, capture stderr
        if proc.poll() is not None or not ready:
            if proc.poll() is not None:
                _, stderr_data = proc.communicate(timeout=5)
                proc = None
            else:
                # Process is running but listeners not ready - still provide proc
                # so the test can check further
                pass

        yield proc, stderr_data, config_path

    finally:
        if proc is not None:
            terminate_process(proc)
