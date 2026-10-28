"""module: readiness; responsibility: receive child startup completion.
Public operations: Readiness.{address,wait_for,close}.
Data entities: Readiness. Tests: notified_process_tests.py through process API.
"""

import selectors
import socket
import tempfile
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

    def wait_for(self, pid: int) -> bool:
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
            while True:
                # Startup completion is an explicit child notification.
                # Keep waiting through unrelated signals/status updates; an
                # exit event ends the wait even if READY was never emitted.
                events = selector.select()
                if any(key.fd == exited.fileno() for key, _ in events):
                    return False
                if not any(key.fd == self._socket.fileno() for key, _ in events):
                    continue
                message = self._socket.recv(4096)
                if b"READY=1" in message.splitlines():
                    self._received = True
                    self.close()
                    return True

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._socket.close()
            self._directory.cleanup()
