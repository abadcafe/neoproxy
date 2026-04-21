"""
Helper functions for integration tests.

This module provides reusable helper functions for integration testing
neoproxy server behavior.
"""

import subprocess
import socket
import threading
import tempfile
import time
import os
import signal
import sys
from typing import Optional, Tuple, List, Callable, Generator

# ==============================================================================
# Constants
# ==============================================================================

NEOPROXY_BINARY = "target/release/neoproxy"


# ==============================================================================
# Binary Check
# ==============================================================================


def check_binary_exists() -> bool:
    """
    Check if the neoproxy binary exists.

    Returns:
        bool: True if binary exists, False otherwise
    """
    return os.path.exists(NEOPROXY_BINARY)


def assert_binary_exists() -> None:
    """
    Assert that the neoproxy binary exists.

    Raises:
        AssertionError: If binary does not exist
    """
    if not check_binary_exists():
        print(
            f"\nERROR: neoproxy binary not found at {NEOPROXY_BINARY}\n"
            f"Please run 'cargo build' before running integration tests.\n",
            file=sys.stderr
        )
        sys.exit(1)

# Listener shutdown timeout: 3 seconds (per design doc)
LISTENER_SHUTDOWN_TIMEOUT = 3

# Service (tunnel) shutdown timeout: 5 seconds (per design doc)
SERVICE_SHUTDOWN_TIMEOUT = 5

# Total max shutdown time: 3 + 5 = 8 seconds
MAX_SHUTDOWN_TIME = LISTENER_SHUTDOWN_TIMEOUT + SERVICE_SHUTDOWN_TIMEOUT


# ==============================================================================
# Configuration Helpers
# ==============================================================================


def create_test_config(
    proxy_port: int,
    temp_dir: str,
    worker_threads: int = 1
) -> str:
    """
    Create test configuration file for CONNECT TCP service.

    Args:
        proxy_port: Port for the proxy server
        temp_dir: Temporary directory for logs
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http_connect
  listeners:
  - kind: hyper.listener
    args:
      addresses: [ "0.0.0.0:{proxy_port}" ]
      protocols: [ http ]
      hostnames: []
      certificates: []
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "test_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_echo_config(
    proxy_port: int,
    temp_dir: str,
    worker_threads: int = 1
) -> str:
    """
    Create echo service configuration file.

    Args:
        proxy_port: Port for the proxy server
        temp_dir: Temporary directory for logs
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: echo_server
  listeners:
  - kind: hyper.listener
    args:
      addresses: [ "0.0.0.0:{proxy_port}" ]
      protocols: [ http ]
      hostnames: []
      certificates: []
  service: echo
"""
    config_path = os.path.join(temp_dir, "echo_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_invalid_config(temp_dir: str) -> str:
    """
    Create invalid YAML configuration file for testing error handling.

    Args:
        temp_dir: Temporary directory

    Returns:
        str: Path to the invalid configuration file
    """
    config_content = "worker_threads: [\n  invalid yaml\n"
    config_path = os.path.join(temp_dir, "invalid.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# Process Management Helpers
# ==============================================================================


def start_proxy(config_path: str) -> subprocess.Popen:
    """
    Start proxy server process.

    Args:
        config_path: Path to configuration file

    Returns:
        subprocess.Popen: Proxy server process
    """
    proc = subprocess.Popen(
        [NEOPROXY_BINARY, "--config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False
    )
    return proc


def wait_for_proxy(
    host: str,
    port: int,
    timeout: float = 5.0,
    interval: float = 0.1
) -> bool:
    """
    Wait for proxy server to be ready.

    Args:
        host: Proxy server host
        port: Proxy server port
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        bool: True if server is ready, False if timeout
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def wait_for_process_exit(
    proc: subprocess.Popen,
    timeout: float = 10.0
) -> Tuple[int, float]:
    """
    Wait for process to exit and return exit code and elapsed time.

    Args:
        proc: Process to wait for
        timeout: Maximum wait time in seconds

    Returns:
        Tuple[int, float]: Exit code and elapsed time in seconds

    Raises:
        AssertionError: If process does not exit within timeout
    """
    start_time = time.time()
    try:
        return_code = proc.wait(timeout=timeout)
        elapsed = time.time() - start_time
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        elapsed = time.time() - start_time
        raise AssertionError(
            f"Process did not exit within expected time (elapsed: {elapsed:.1f}s)"
        )
    return return_code, elapsed


def terminate_process(proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """
    Terminate a process gracefully, then kill if needed.

    Args:
        proc: Process to terminate
        timeout: Time to wait for graceful termination
    """
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


# ==============================================================================
# Network Helpers
# ==============================================================================


def create_target_server(
    host: str,
    port: int,
    handler: Callable[[socket.socket], None]
) -> Tuple[threading.Thread, socket.socket]:
    """
    Create a mock target server for testing.

    Args:
        host: Listen address
        port: Listen port
        handler: Connection handler function

    Returns:
        Tuple[threading.Thread, socket.socket]: Server thread and socket
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    running = threading.Event()
    running.set()

    def server_loop() -> None:
        while running.is_set():
            try:
                server_socket.settimeout(0.5)
                conn, _ = server_socket.accept()
                thread = threading.Thread(target=handler, args=(conn,))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception:
                break

    thread = threading.Thread(target=server_loop)
    thread.daemon = True
    thread.start()

    return thread, server_socket


def establish_connect_tunnel(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int
) -> Optional[socket.socket]:
    """
    Establish a CONNECT tunnel through the proxy.

    Args:
        proxy_host: Proxy server host
        proxy_port: Proxy server port
        target_host: Target server host
        target_port: Target server port

    Returns:
        Optional[socket.socket]: Socket if tunnel established, None otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((proxy_host, proxy_port))

        connect_request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n\r\n"
        ).encode()
        sock.sendall(connect_request)

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk

        if b"200" in response:
            return sock
        else:
            sock.close()
            return None
    except Exception:
        sock.close()
        return None


def send_raw_request(
    host: str,
    port: int,
    request: bytes,
    timeout: float = 5.0
) -> bytes:
    """
    Send raw HTTP request and read response.

    Args:
        host: Target host
        port: Target port
        request: Raw HTTP request bytes
        timeout: Socket timeout in seconds

    Returns:
        bytes: Response data
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(request)

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            # If we got a complete HTTP response header, stop
            if b"\r\n\r\n" in response:
                break
        return response
    finally:
        sock.close()


def is_port_available(host: str, port: int) -> bool:
    """
    Check if a port is available for binding.

    Args:
        host: Host address
        port: Port number

    Returns:
        bool: True if port is available, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        result = sock.connect_ex((host, port))
        return result != 0
    except Exception:
        return True
    finally:
        sock.close()


# ==============================================================================
# Signal Helpers
# ==============================================================================


def send_sigint(proc: subprocess.Popen) -> None:
    """
    Send SIGINT signal to a process.

    Args:
        proc: Process to signal
    """
    proc.send_signal(signal.SIGINT)


def send_sigterm(proc: subprocess.Popen) -> None:
    """
    Send SIGTERM signal to a process.

    Args:
        proc: Process to signal
    """
    proc.send_signal(signal.SIGTERM)


# ==============================================================================
# Assertion Helpers
# ==============================================================================


def assert_exit_code(
    actual: int,
    expected: int,
    context: Optional[str] = None
) -> None:
    """
    Assert that exit code matches expected value.

    Args:
        actual: Actual exit code
        expected: Expected exit code
        context: Optional context message for assertion error

    Raises:
        AssertionError: If exit codes don't match
    """
    msg = f"Expected exit code {expected}, got {actual}"
    if context:
        msg = f"{context}: {msg}"
    assert actual == expected, msg


def assert_process_exits_within(
    proc: subprocess.Popen,
    max_time: float,
    expected_exit_code: Optional[int] = None
) -> Tuple[int, float]:
    """
    Assert that process exits within specified time.

    Args:
        proc: Process to wait for
        max_time: Maximum time in seconds
        expected_exit_code: Expected exit code (optional)

    Returns:
        Tuple[int, float]: Exit code and elapsed time

    Raises:
        AssertionError: If process doesn't exit in time or exit code is wrong
    """
    start_time = time.time()
    try:
        return_code = proc.wait(timeout=max_time)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        elapsed = time.time() - start_time
        raise AssertionError(
            f"Process did not exit within {max_time}s (elapsed: {elapsed:.1f}s)"
        )
    elapsed = time.time() - start_time

    if expected_exit_code is not None:
        assert_exit_code(
            return_code,
            expected_exit_code,
            f"Process exited in {elapsed:.1f}s"
        )

    return return_code, elapsed


# ==============================================================================
# Handler Functions for Target Servers
# ==============================================================================


def echo_handler(conn: socket.socket) -> None:
    """
    Echo handler that sends back received data with prefix.

    Args:
        conn: Client connection socket
    """
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.send(b"ECHO:" + data)
    except Exception:
        pass
    finally:
        conn.close()


def blocking_handler(conn: socket.socket, block_time: float = 60.0) -> None:
    """
    Blocking handler that keeps connection open for specified time.

    Args:
        conn: Client connection socket
        block_time: Time to block in seconds
    """
    try:
        time.sleep(block_time)
    except Exception:
        pass
    finally:
        conn.close()


def http_echo_handler(conn: socket.socket) -> None:
    """
    HTTP echo handler that returns a valid HTTP response.

    Args:
        conn: Client connection socket
    """
    try:
        data = conn.recv(1024)
        if data:
            http_response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 2\r\n"
                b"\r\n"
                b"OK"
            )
            conn.send(http_response)
    except Exception:
        pass
    finally:
        conn.close()


# ==============================================================================
# Environment Helpers
# ==============================================================================


def get_curl_env_without_no_proxy() -> dict:
    """
    Get a copy of the environment with no_proxy cleared for curl.

    This is needed to force curl to use the proxy for localhost addresses,
    which are normally excluded by no_proxy environment variables.

    Returns:
        dict: Environment dict with no_proxy and NO_PROXY cleared
    """
    env = os.environ.copy()
    env["no_proxy"] = ""
    env["NO_PROXY"] = ""
    return env
