"""module: proxy_process; responsibility: proxy process fixtures.
Public operations: start_proxy, wait_for_process_exit, wait_for_process_running,
terminate_process, send_sigint, assert_exit_code, assert_process_exits_within,
managed_processes.
Data entities: BytesProcess, ProcessFactory.
Tests: proxy_process_tests.py and public fixture consumers.
"""

import os
import signal
import subprocess
import time
from collections.abc import Callable, Generator
from contextlib import ExitStack, contextmanager

from .binary import NEOPROXY_BINARY

type BytesProcess = subprocess.Popen[bytes]
type ProcessFactory = Callable[[str], BytesProcess]


# Listener and upstream task waits: (3s + 2s) + (3s + 2s).
# This excludes log flushing and other process teardown.
MAX_SHUTDOWN_TIME = 10


def start_proxy(config_path: str) -> BytesProcess:
    """
    Start proxy server process.

    Args:
        config_path: Path to configuration file

    Returns:
        subprocess.Popen: Proxy server process
    """
    binary = os.path.abspath(NEOPROXY_BINARY)
    proc = subprocess.Popen(
        [binary, "--config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        cwd=os.path.dirname(config_path),
    )
    return proc


@contextmanager
def managed_processes() -> Generator[ProcessFactory, None, None]:
    """Own all proxy children created through a factory until context exit."""
    with ExitStack() as resources:

        def start(config_path: str) -> BytesProcess:
            process = resources.enter_context(start_proxy(config_path))
            # Terminate and reap before Popen's context closes its pipes.
            # ExitStack also runs these actions when the caller fails.
            _ = resources.callback(terminate_process, process)
            return process

        yield start


def wait_for_process_exit(
    proc: BytesProcess, timeout: float = 10.0
) -> tuple[int, float]:
    """
    Wait for process to exit and return exit code and elapsed time.

    Args:
        proc: Process to wait for
        timeout: Maximum wait time in seconds

    Returns:
        tuple[int, float]: Exit code and elapsed time in seconds

    Raises:
        AssertionError: If process does not exit within timeout
    """
    start_time = time.monotonic()
    try:
        return_code = proc.wait(timeout=timeout)
        elapsed = time.monotonic() - start_time
    except subprocess.TimeoutExpired:
        proc.kill()
        _ = proc.wait()
        elapsed = time.monotonic() - start_time
        raise AssertionError(
            f"Process did not exit within expected time (elapsed: {elapsed:.1f}s)"
        )
    return return_code, elapsed


def wait_for_process_running(
    proc: BytesProcess, timeout: float = 1.0, interval: float = 0.05
) -> bool:
    """
    Wait for a process to be running (not exited).

    Polls proc.poll() at short intervals. Returns True if the process
    is still running after polling for the timeout duration.
    Returns False if the process exits during the wait.

    Args:
        proc: Process to check
        timeout: Maximum time to confirm the process stays running
        interval: Poll interval in seconds

    Returns:
        bool: True if process is still running, False if it exited
    """
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        if proc.poll() is not None:
            return False
        time.sleep(interval)
    return proc.poll() is None


def terminate_process(
    proc: BytesProcess, timeout: float = 5.0, force: bool = False
) -> None:
    """
    Terminate a process gracefully, then kill if needed.

    Args:
        proc: Process to terminate
        timeout: Time to wait for graceful termination
        force: If True, send SIGKILL immediately (no graceful shutdown)
    """
    if proc.poll() is None:
        if force:
            proc.kill()
        else:
            proc.terminate()
        try:
            _ = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            _ = proc.wait()


def send_sigint(proc: BytesProcess) -> None:
    """
    Send SIGINT signal to a process.

    Args:
        proc: Process to signal
    """
    proc.send_signal(signal.SIGINT)


def assert_exit_code(actual: int, expected: int, context: str | None = None) -> None:
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
    proc: BytesProcess,
    max_time: float,
    expected_exit_code: int | None = None,
) -> tuple[int, float]:
    """
    Assert that process exits within specified time.

    Args:
        proc: Process to wait for
        max_time: Maximum time in seconds
        expected_exit_code: Expected exit code (optional)

    Returns:
        tuple[int, float]: Exit code and elapsed time

    Raises:
        AssertionError: If process doesn't exit in time or exit code is wrong
    """
    start_time = time.monotonic()
    try:
        return_code = proc.wait(timeout=max_time)
    except subprocess.TimeoutExpired:
        proc.kill()
        _ = proc.wait()
        elapsed = time.monotonic() - start_time
        raise AssertionError(
            f"Process did not exit within {max_time}s (elapsed: {elapsed:.1f}s)"
        )
    elapsed = time.monotonic() - start_time

    if expected_exit_code is not None:
        assert_exit_code(
            return_code,
            expected_exit_code,
            f"Process exited in {elapsed:.1f}s",
        )

    return return_code, elapsed
