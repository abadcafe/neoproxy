"""module: ports; responsibility: allocate and observe test ports.
Public operations: get_unique_port, wait_for_port_released.
Data entities: none.
Tests: sibling module tests and public fixture consumers.
"""

import errno
import fcntl
import socket
import time
from collections.abc import Iterator
from contextlib import ExitStack

from .binary import PROJECT_ROOT


def _release_windows(timeout: float, interval: float) -> Iterator[float]:
    """Observe port release with bounded backoff and one deadline."""
    deadline = time.monotonic() + timeout
    delay = min(interval, 0.001)
    while (remaining := deadline - time.monotonic()) > 0:
        yield remaining
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, interval)


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
        interval: Maximum poll interval in seconds

    Returns:
        bool: True if port was released, False on timeout
    """
    for remaining in _release_windows(timeout, interval):
        try:
            probe = socket.create_connection((host, port), timeout=min(0.5, remaining))
        except OSError as error:
            if error.errno == errno.ECONNREFUSED:
                return True
        else:
            probe.close()
    return False


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
    # Probing alone cannot stop independent workers returning the same
    # still-unbound candidate. Share the counter across test processes.
    counter_path = PROJECT_ROOT / "tmp" / "test-port-counter"
    counter_path.parent.mkdir(parents=True, exist_ok=True)
    with counter_path.open("a+", encoding="ascii") as counter:
        fcntl.flock(counter, fcntl.LOCK_EX)
        _ = counter.seek(0)
        saved = counter.read().strip()
        port = int(saved) if saved else 28000
        for _ in range(100):  # Limit attempts to avoid infinite loop
            port = port + 1 if port < 65534 else 28001

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
                    _ = counter.seek(0)
                    _ = counter.truncate()
                    _ = counter.write(str(port))
                    counter.flush()
                    return port
            except OSError:
                # Port is not available, try next one
                continue

        assert False, "Could not find an available port after 100 attempts"
