"""
pytest configuration and fixtures for integration tests.

This module provides fixtures for managing test environments,
including temporary directories, proxy processes, and mock servers.
"""

import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Generator

import pytest

from .types import (
    BytesProcess,
    ConfigDict,
    HttpServerInfo,
    IdleConnectionFactory,
    JsonValue,
    PortFactory,
    ProcessFactory,
    ProxyContext,
    ProxyWithConfig,
    StringMap,
    TargetHandler,
    TargetHttpServerFactory,
    TargetServerFactory,
    WaitReady,
)
from .utils.helpers import (
    NEOPROXY_BINARY,
    build_neoproxy_binary,
    check_binary_exists,
    create_echo_config,
    create_target_server,
    create_test_config,
    start_proxy,
    terminate_process,
    wait_for_proxy,
)

# ==============================================================================
# Port Management
# ==============================================================================

# Global port counter to avoid port conflicts between tests
_port_counter = 28000
_port_lock = threading.Lock()


def get_unique_port() -> int:
    """
    Get a unique port number for testing.

    This function verifies that the port is actually available by attempting
    to bind to it WITHOUT SO_REUSEADDR. This ensures the port is truly free
    (not in TIME_WAIT state). If the port is not available, it tries the next
    port until an available one is found.

    Why no SO_REUSEADDR:
    - neoproxy server does NOT set SO_REUSEADDR on its listening sockets
    - If we used SO_REUSEADDR here, we could bind ports in TIME_WAIT state
    - But neoproxy would then fail to bind those same ports
    - This caused "works in suite, fails alone" bugs

    Returns:
        int: Available port number

    Raises:
        RuntimeError: If no available port can be found after 100 attempts
    """
    global _port_counter
    with _port_lock:
        for _ in range(100):  # Limit attempts to avoid infinite loop
            _port_counter += 1
            port = _port_counter

            # Verify the port is actually available by trying to bind
            # Do NOT use SO_REUSEADDR - we want truly free ports
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_sock:
                    # Don't use SO_REUSEADDR - this ensures port is truly free
                    test_sock.bind(("0.0.0.0", port))
                    return port
            except OSError:
                # Port is not available, try next one
                continue

        raise RuntimeError("Could not find an available port after 100 attempts")


# ==============================================================================
# Layer Test Fixtures
# ==============================================================================


@pytest.fixture
def proxy_with_config(temp_dir: str) -> Generator[ProxyWithConfig, None, None]:
    """Start proxy with a given config dict, yield a context manager.

    Usage:
        with proxy_with_config(config_dict) as proxy:
            # proxy.port - the port the proxy is listening on
            # proxy.working_dir - the temp directory
            # proxy.process - the subprocess.Popen object
    """

    @contextlib.contextmanager
    def _proxy_with_config(
        config_dict: ConfigDict,
    ) -> Generator[ProxyContext, None, None]:
        port = get_unique_port()
        # Update listener addresses to use the allocated port
        listeners = config_dict.get("listeners", [])
        assert isinstance(listeners, list)
        for listener in listeners:
            assert isinstance(listener, dict)
            addrs = listener.get("addresses", [])
            assert isinstance(addrs, list)
            listener["addresses"] = [
                addr.replace("AUTO_PORT", str(port)) if isinstance(addr, str) and "AUTO_PORT" in addr else addr
                for addr in addrs
            ]
            # If no addresses were specified or all were empty, default to 127.0.0.1:port
            if not listener["addresses"]:
                listener["addresses"] = [f"127.0.0.1:{port}"]

        config_path = os.path.join(temp_dir, f"config_{port}.yaml")
        yaml_content = dict_to_yaml(config_dict)
        with open(config_path, "w") as f:
            f.write(yaml_content)

        # Resolve binary path to absolute path since cwd changes to temp_dir
        binary_path = os.path.abspath(NEOPROXY_BINARY)
        proc = subprocess.Popen(
            [binary_path, "--config", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=temp_dir,
        )
        if not wait_for_proxy("127.0.0.1", port, timeout=2.0, proc=proc):
            terminate_process(proc, timeout=0.5, force=True)
            raise RuntimeError(f"Proxy did not start on port {port}")

        ctx = ProxyContext(proc, port, temp_dir)
        try:
            yield ctx
        finally:
            terminate_process(proc, timeout=0.5, force=True)

    yield _proxy_with_config


def dict_to_yaml(config: ConfigDict) -> str:
    """Convert a config dict to YAML string manually.

    Avoids yaml.dump() formatting issues with the Rust serde_yaml parser.
    All top-level keys are rendered generically via _yaml_value, which handles
    dicts, lists, lists-of-dicts, strings, booleans, and nulls. This ensures
    any new config key (e.g. tls, plugins) is rendered correctly without
    silent data loss.
    """
    lines: list[str] = []

    for key, value in config.items():
        lines.extend(_yaml_value(key, value, indent=0))

    return "\n".join(lines) + "\n"


def _yaml_dict(d: dict[str, JsonValue], indent: int, key: str | None = None) -> list[str]:
    """Render a dict as YAML key-value lines with proper indentation.

    Args:
        d: The dictionary to render.
        indent: The indentation level (number of spaces) for the first key.
        key: Optional parent key name. If provided, the key is rendered first.

    Returns:
        List of YAML lines.
    """
    prefix = " " * indent
    lines: list[str] = []
    if key is not None:
        lines.append(f"{prefix}{key}:")
        indent += 2
        prefix = " " * indent

    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            sub_lines = _yaml_dict(v, indent=indent + 2)
            lines.extend(sub_lines)
        elif isinstance(v, list):
            # Check if it's a list of dicts (sequence of mappings)
            if v and isinstance(v[0], dict):
                lines.append(f"{prefix}{k}:")
                for item in v:
                    assert isinstance(item, dict)
                    lines.append(f"{prefix}  -")
                    for ik, iv in item.items():
                        lines.extend(_yaml_value(ik, iv, indent=indent + 4))
            else:
                lines.append(f"{prefix}{k}: {json.dumps(v)}")
        elif isinstance(v, str):
            lines.append(f'{prefix}{k}: "{v}"')
        elif isinstance(v, bool):
            lines.append(f"{prefix}{k}: {'true' if v else 'false'}")
        elif v is None:
            lines.append(f"{prefix}{k}: null")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return lines


def _yaml_value(key: str, value: JsonValue, indent: int = 0) -> list[str]:
    """Render a single YAML key-value pair, handling dicts, lists, and scalars.

    Used for dynamic keys that don't have special rendering rules.

    Args:
        key: The YAML key.
        value: The value to render.
        indent: The indentation level (number of spaces).

    Returns:
        List of YAML lines.
    """
    prefix = " " * indent
    lines: list[str] = []
    if isinstance(value, dict):
        lines.append(f"{prefix}{key}:")
        lines.extend(_yaml_dict(value, indent=indent + 2))
    elif isinstance(value, list):
        # Check if it's a list of dicts (sequence of mappings)
        if value and isinstance(value[0], dict):
            lines.append(f"{prefix}{key}:")
            for item in value:
                assert isinstance(item, dict)
                lines.append(f"{prefix}  -")
                for ik, iv in item.items():
                    lines.extend(_yaml_value(ik, iv, indent=indent + 4))
        else:
            lines.append(f"{prefix}{key}: {json.dumps(value)}")
    elif isinstance(value, str):
        lines.append(f'{prefix}{key}: "{value}"')
    elif isinstance(value, bool):
        lines.append(f"{prefix}{key}: {'true' if value else 'false'}")
    elif value is None:
        lines.append(f"{prefix}{key}: null")
    else:
        lines.append(f"{prefix}{key}: {value}")
    return lines


@pytest.fixture
def target_http_server(available_port: PortFactory) -> Generator[TargetHttpServerFactory, None, None]:
    """Start a simple HTTP echo server, yield the server info.

    Usage:
        with target_http_server() as server:
            # server.port - the port the server is listening on
            # server.url - base URL like "http://127.0.0.1:PORT"
    """

    @contextlib.contextmanager
    def _target_http_server() -> Generator[HttpServerInfo, None, None]:
        port = available_port()
        from .utils.helpers import http_echo_handler

        _thread, sock = create_target_server("127.0.0.1", port, http_echo_handler)
        assert wait_for_proxy("127.0.0.1", port, timeout=2.0), f"Target HTTP server failed to start on port {port}"
        info = HttpServerInfo(port, sock)
        try:
            yield info
        finally:
            sock.close()

    yield _target_http_server


# ==============================================================================
# Directory Fixtures
# ==============================================================================


@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """
    Provide a temporary directory for test files.

    Yields:
        str: Path to temporary directory

    Cleanup:
        Removes directory after test completes.
    """
    dir_path = tempfile.mkdtemp(prefix="neoproxy_test_")
    yield dir_path
    shutil.rmtree(dir_path, ignore_errors=True)


# ==============================================================================
# Configuration Fixtures
# ==============================================================================


@pytest.fixture
def proxy_config(temp_dir: str) -> Generator[str, None, None]:
    """
    Provide a CONNECT TCP configuration file.

    Args:
        temp_dir: Temporary directory fixture

    Yields:
        str: Path to configuration file
    """
    port = get_unique_port()
    config_path = create_test_config(port, temp_dir)
    yield config_path


@pytest.fixture
def echo_config(temp_dir: str) -> Generator[str, None, None]:
    """
    Provide an echo service configuration file.

    Args:
        temp_dir: Temporary directory fixture

    Yields:
        str: Path to configuration file
    """
    port = get_unique_port()
    config_path = create_echo_config(port, temp_dir)
    yield config_path


# ==============================================================================
# Process Fixtures
# ==============================================================================


@pytest.fixture
def proxy_process() -> Generator[ProcessFactory, None, None]:
    """
    Provide a factory to create and manage proxy processes.

    Yields:
        Callable that creates proxy processes. Processes are automatically
        terminated after the test.

    Usage:
        def test_example(proxy_process):
            proc = proxy_process(config_path, port)
            # ... test code ...
    """
    processes: list[BytesProcess] = []

    def create_process(config_path: str, port: int | None = None) -> BytesProcess:
        """
        Create and register a proxy process.

        Args:
            config_path: Path to configuration file
            port: Optional port (for waiting for ready)

        Returns:
            subprocess.Popen: The proxy process
        """
        proc = start_proxy(config_path)
        processes.append(proc)
        return proc

    yield create_process

    # Cleanup: terminate all registered processes
    for proc in processes:
        terminate_process(proc)


# ==============================================================================
# Server Fixtures
# ==============================================================================


@pytest.fixture
def target_server() -> Generator[TargetServerFactory, None, None]:
    """
    Provide a factory to create mock target servers.

    Yields:
        Callable that creates target servers. Servers are automatically
        stopped after the test.

    Usage:
        def test_example(target_server):
            def handler(conn):
                conn.send(b"HELLO")
                conn.close()

            server_socket = target_server(port, handler)
    """
    sockets: list[socket.socket] = []

    def create_server(port: int, handler: TargetHandler) -> socket.socket:
        """
        Create and register a mock target server.

        Args:
            port: Port to listen on
            handler: Connection handler function

        Returns:
            socket.socket: The server socket
        """
        _, server_socket = create_target_server("127.0.0.1", port, handler)
        sockets.append(server_socket)
        return server_socket

    yield create_server

    # Cleanup: close all registered sockets
    for sock in sockets:
        sock.close()


# ==============================================================================
# Connection Fixtures
# ==============================================================================


@pytest.fixture
def idle_connection() -> Generator[IdleConnectionFactory, None, None]:
    """
    Provide a factory to create idle connections.

    Yields:
        Callable that creates idle connections. Connections are automatically
        closed after the test.
    """
    connections: list[socket.socket] = []

    def create_connection(host: str, port: int) -> socket.socket:
        """
        Create and register an idle connection.

        Args:
            host: Target host
            port: Target port

        Returns:
            socket.socket: The connection socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        connections.append(sock)
        return sock

    yield create_connection

    # Cleanup: close all registered connections
    for conn in connections:
        conn.close()


# ==============================================================================
# Ready Check Fixture
# ==============================================================================


@pytest.fixture
def wait_ready() -> WaitReady:
    """
    Provide a function to wait for proxy server to be ready.

    Returns:
        Callable that waits for server readiness.
    """

    def wait(host: str, port: int, timeout: float = 5.0) -> bool:
        return wait_for_proxy(host, port, timeout)

    return wait


# ==============================================================================
# Port Fixture
# ==============================================================================


@pytest.fixture
def available_port() -> PortFactory:
    """
    Provide a function to get unique available ports.

    Returns:
        Callable that returns unique port numbers.
    """
    return get_unique_port


# ==============================================================================
# Session-scoped Certificate Cache
# ==============================================================================


@pytest.fixture(scope="session")
def shared_certs_dir() -> Generator[str, None, None]:
    """
    Session-scoped directory for shared test certificates.

    This directory persists across all tests in the session,
    allowing certificate generation to be cached and reused.
    """
    cert_dir = tempfile.mkdtemp(prefix="neoproxy_certs_")
    yield cert_dir
    shutil.rmtree(cert_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def shared_test_certs(shared_certs_dir: str) -> StringMap:
    """
    Session-scoped TLS test certificates.

    Generates a CA certificate and a server certificate signed by that CA.
    Shared across all tests in the session to avoid repeated openssl calls
    (~0.2s per call, ~97 calls total without caching).

    Returns:
        Dict with keys: cert_path, key_path, ca_path, ca_key_path
    """
    from .utils.certs import generate_test_certificates

    cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(shared_certs_dir)
    return {
        "cert_path": cert_path,
        "key_path": key_path,
        "ca_path": ca_path,
        "ca_key_path": ca_key_path,
    }


@pytest.fixture(scope="session")
def shared_client_cert(shared_certs_dir: str, shared_test_certs: StringMap) -> StringMap:
    """
    Session-scoped client certificate for mTLS tests.

    Generates a client certificate signed by the same CA as shared_test_certs.
    Shared across all tests that need a valid client certificate.

    Returns:
        Dict with keys: client_cert_path, client_key_path
    """
    from .utils.certs import generate_client_cert

    client_cert_path, client_key_path = generate_client_cert(
        shared_certs_dir,
        shared_test_certs["ca_path"],
        shared_test_certs["ca_key_path"],
    )
    return {
        "client_cert_path": client_cert_path,
        "client_key_path": client_key_path,
    }


# ==============================================================================
# pytest Configuration
# ==============================================================================


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers and check binary exists."""
    build_neoproxy_binary()
    if not check_binary_exists():
        print(
            f"\nERROR: neoproxy binary not found at {NEOPROXY_BINARY}\n"
            f"Please run 'cargo build' or set NEOPROXY_BINARY.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Add default markers to integration tests."""
    for item in items:
        # Mark all tests in integration directory as integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
