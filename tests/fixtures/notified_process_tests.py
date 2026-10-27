"""Public notification and resource ownership contracts for ProxyProcess."""

import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tests.fixtures.notified_process import ProxyProcess

_CHILD = """import os
import socket
import sys

print(os.environ['NOTIFY_SOCKET'], flush=True)
for command in sys.stdin:
    if command.strip() == 'exit':
        break
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notice:
        _ = notice.sendto(command.strip().encode(), os.environ['NOTIFY_SOCKET'])
"""


def send(process: ProxyProcess, message: bytes) -> None:
    assert process.stdin is not None
    _ = process.stdin.write(message + b"\n")
    process.stdin.flush()


def test_wait_ready_receives_notification_without_sleeping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with ProxyProcess([sys.executable, "-c", _CHILD], stdin=subprocess.PIPE) as process:
        assert process.stdout is not None
        path = Path(process.stdout.readline().decode().strip())
        assert path.is_socket()

        def forbid_sleep(seconds: float) -> None:
            pytest.fail(f"readiness must wait for an event, not sleep {seconds}s")

        ready = threading.Timer(0.02, send, args=(process, b"READY=1"))
        ready.start()
        try:
            with monkeypatch.context() as check:
                check.setattr(time, "sleep", forbid_sleep)
                assert process.wait_ready(timeout=2)
                assert process.wait_ready(timeout=0)
            assert not path.exists()
        finally:
            ready.join()
            send(process, b"exit")
        assert process.wait(timeout=2) == 0
        assert not process.wait_ready(timeout=0)


def test_wait_ready_observes_child_exit_without_a_notification() -> None:
    with ProxyProcess([sys.executable, "-c", "pass"]) as process:
        assert not process.wait_ready(timeout=2)
        assert process.wait(timeout=2) == 0


def test_wait_ready_timeout_does_not_invent_readiness_and_can_be_retried() -> None:
    with ProxyProcess([sys.executable, "-c", _CHILD], stdin=subprocess.PIPE) as process:
        assert process.stdout is not None
        path = Path(process.stdout.readline().decode().strip())
        try:
            assert not process.wait_ready(timeout=0.01)
            send(process, b"STATUS=starting")
            assert not process.wait_ready(timeout=0.01)
            send(process, b"READY=1")
            assert process.wait_ready(timeout=2)
        finally:
            send(process, b"exit")
        assert process.wait(timeout=2) == 0
        assert not path.exists()


def test_wait_closes_notification_resources_even_when_readiness_was_not_awaited() -> (
    None
):
    with ProxyProcess([sys.executable, "-c", _CHILD], stdin=subprocess.PIPE) as process:
        assert process.stdout is not None
        path = Path(process.stdout.readline().decode().strip())
        send(process, b"exit")
        assert process.wait(timeout=2) == 0
        assert not path.exists()
