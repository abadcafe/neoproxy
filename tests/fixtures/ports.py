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
from contextlib import ExitStack

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

        try:
            probe = socket.create_connection((host, port), timeout=1.0)
        except OSError:
            pass
        else:
            probe.close()
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
        try:
            probe = socket.create_connection((host, port), timeout=0.5)
        except OSError as error:
            if error.errno == errno.ECONNREFUSED:
                return True
        else:
            probe.close()
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

        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        test_sock = socket.socket(family, socket.SOCK_DGRAM)
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

    Probe TCP and UDP in each available IP family without reuse options.
    A QUIC listener needs UDP availability even when the TCP port is free.
    Keep every probe socket open until all families/transports have passed;
    IPv6-only probes avoid colliding with our own IPv4 probes.

    Returns:
        int: Available port number

    Resource exhaustion fails the fixture's assertion after 100 candidates.
    """
    global _port_counter
    with _port_lock:
        for _ in range(100):  # Limit attempts to avoid infinite loop
            _port_counter += 1
            port = _port_counter

            try:
                with ExitStack() as probes:
                    families = [(socket.AF_INET, "0.0.0.0")]
                    if socket.has_ipv6:
                        families.append((socket.AF_INET6, "::"))
                    for family, host in families:
                        for transport in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                            probe = probes.enter_context(
                                socket.socket(family, transport)
                            )
                            if family == socket.AF_INET6:
                                probe.setsockopt(
                                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1
                                )
                            probe.bind((host, port))
                    return port
            except OSError:
                # Port is not available, try next one
                continue

        assert False, "Could not find an available port after 100 attempts"
