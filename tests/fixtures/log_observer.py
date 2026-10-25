"""module: log_observer; responsibility: log observer fixtures.
Public operations: wait_for_log_contains.
Tests: sibling module tests and public fixture consumers.
"""

import time


def wait_for_log_contains(
    log_path: str,
    pattern: str,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    """
    Wait for log file to contain a specific pattern.

    Args:
        log_path: Path to log file
        pattern: String pattern to search for
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        bool: True if pattern found, False if timeout
    """
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        try:
            with open(log_path, "r") as f:
                if pattern in f.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(interval)
    return False
