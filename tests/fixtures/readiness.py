"""module: readiness; responsibility: receive child startup completion.
Public operations: Readiness.{address,wait_for,close}.
Data entities: Readiness. Tests: notified_process_tests.py through process API.
"""

import selectors
import socket
import tempfile
import time
from contextlib import ExitStack

from .process_exit import ExitNotification


class Readiness:
    def __init__(self) -> None:
        self._directory: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
            prefix="np-ready-", dir="/tmp"
        )
        self._address: str = self._directory.name + "/notify"
        self._socket: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._socket.bind(self._address)
        self._received: bool = False
        self._closed: bool = False

    @property
    def address(self) -> str:
        return self._address

    def wait_for(self, pid: int, timeout: float) -> bool:
        if self._received:
            return True
        if self._closed:
            return False
        try:
            exited = ExitNotification(pid)
        except ProcessLookupError:
            return False
        with ExitStack() as resources:
            _ = resources.enter_context(exited)
            selector = resources.enter_context(selectors.DefaultSelector())
            _ = selector.register(self._socket, selectors.EVENT_READ)
            _ = selector.register(exited, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while True:
                events = selector.select(max(0, deadline - time.monotonic()))
                if not events or any(key.fd == exited.fileno() for key, _ in events):
                    return False
                message = self._socket.recv(4096)
                if b"READY=1" in message.splitlines():
                    self._received = True
                    self.close()
                    return True
                if time.monotonic() >= deadline:
                    return False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._socket.close()
            self._directory.cleanup()
