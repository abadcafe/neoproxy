"""module: ports; responsibility: allocate and observe test ports.
Public operations: get_unique_port, wait_for_proxy, wait_for_port_released,
wait_for_udp_port_bound.
Data entities: none.
Tests: sibling module tests and public fixture consumers.
"""

import errno
import socket
import threading
import time

from .proxy_process import BytesProcess


def wait_for_proxy(
    host: str,
    port: int,
    timeout: float = 5.0,
    interval: float = 0.1,
    proc: BytesProcess | None = None,
) -> bool:
    """
    Wait for proxy server to be ready.

    Args:
        host: Proxy server host
        port: Proxy server port
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        proc: Optional process to check for early termination.
              If process exits, returns False immediately.

    Returns:
        bool: True if server is ready, False if timeout or process exited
    """
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        # Check if process has exited (if provided)
        if proc is not None and proc.poll() is not None:
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            result = sock.connect_ex((host, port))
            if result == 0:
                return True
        time.sleep(interval)
    return False


def wait_for_port_released(
    host: str, port: int, timeout: float = 2.0, interval: float = 0.05
) -> bool:
    """
    Wait for a port to be released (no longer accepting connections).

    Polls connect_ex until it fails (port released) or timeout expires.

    Args:
        host: Host to check
        port: Port to check
        timeout: Maximum wait time in seconds
        interval: Poll interval in seconds

    Returns:
        bool: True if port was released, False on timeout
    """
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result != 0:
                return True
        time.sleep(interval)
    return False


def wait_for_udp_port_bound(
    host: str,
    port: int,
    timeout: float = 5.0,
    interval: float = 0.1,
    proc: BytesProcess | None = None,
) -> bool:
    """
    Wait for UDP port to be bound (indicating server started).

    This function checks if a UDP port is in use by attempting to bind to it.
    If binding fails with EADDRINUSE, the port is bound by another process.

    Args:
        host: Host address
        port: Port number
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds
        proc: Optional process to check for early termination.
              If process exits, returns False immediately.

    Returns:
        bool: True if port is bound by another process, False if timeout or process
        exited
    """
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        # Check if process has exited (if provided)
        if proc is not None and proc.poll() is not None:
            return False

        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            test_sock.bind((host, port))
            # Port is available, server not started yet
        except OSError as e:
            # Only return True if the error is specifically EADDRINUSE.
            if e.errno == errno.EADDRINUSE:
                return True
        finally:
            test_sock.close()
        time.sleep(interval)
    return False


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

        assert False, "Could not find an available port after 100 attempts"
