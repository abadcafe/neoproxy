"""
pytest configuration and fixtures for integration tests.

This module provides fixtures for managing test environments,
including temporary directories, proxy processes, and mock servers.
"""

import subprocess
import socket
import tempfile
import shutil
import threading
import os
import sys
from typing import Optional, Generator, Callable

import pytest

from .utils.helpers import (
    NEOPROXY_BINARY,
    check_binary_exists,
    create_test_config,
    create_echo_config,
    start_proxy,
    terminate_process,
    wait_for_proxy,
    create_target_server,
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

    Returns:
        int: Available port number
    """
    global _port_counter
    with _port_lock:
        _port_counter += 1
        return _port_counter


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
def proxy_process() -> Generator[
    Callable[[str, Optional[int]], subprocess.Popen],
    None,
    None
]:
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
    processes: list[subprocess.Popen] = []

    def create_process(
        config_path: str,
        port: Optional[int] = None
    ) -> subprocess.Popen:
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
def target_server() -> Generator[
    Callable[[int, Callable[[socket.socket], None]], socket.socket],
    None,
    None
]:
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

    def create_server(
        port: int,
        handler: Callable[[socket.socket], None]
    ) -> socket.socket:
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
        try:
            sock.close()
        except Exception:
            pass


# ==============================================================================
# Connection Fixtures
# ==============================================================================


@pytest.fixture
def idle_connection() -> Generator[
    Callable[[str, int], socket.socket],
    None,
    None
]:
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
        try:
            conn.close()
        except Exception:
            pass


# ==============================================================================
# Ready Check Fixture
# ==============================================================================


@pytest.fixture
def wait_ready() -> Callable[[str, int, float], bool]:
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
def available_port() -> Callable[[], int]:
    """
    Provide a function to get unique available ports.

    Returns:
        Callable that returns unique port numbers.
    """
    return get_unique_port


# ==============================================================================
# pytest Configuration
# ==============================================================================


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers and check binary exists."""
    # Check if neoproxy binary exists before running tests
    if not check_binary_exists():
        print(
            f"\nERROR: neoproxy binary not found at {NEOPROXY_BINARY}\n"
            f"Please run 'cargo build' before running integration tests.\n",
            file=sys.stderr
        )
        sys.exit(1)

    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item]
) -> None:
    """Add default markers to integration tests."""
    for item in items:
        # Mark all tests in integration directory as integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)