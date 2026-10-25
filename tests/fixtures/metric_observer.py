"""module: metric_observer; responsibility: metric observer fixtures.
Public operations: wait_for_metric_value.
Tests: sibling module tests and public fixture consumers.
"""

import time
from collections.abc import Callable


def wait_for_metric_value(
    fetch_func: Callable[[], str],
    expected: str,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    """
    Wait for a metric to have a specific value.

    Args:
        fetch_func: Callable that returns the current metric string
        expected: Expected string to find in the response
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        bool: True if expected value found, False if timeout
    """
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        try:
            response = fetch_func()
            if expected in response:
                return True
        except OSError:
            pass
        time.sleep(interval)
    return False
