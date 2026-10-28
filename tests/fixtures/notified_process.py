"""module: notified_process; responsibility: own a startup-notifying child.
Public operations: ProxyProcess.{wait_ready,poll,wait}.
Data entities: ProxyProcess. Tests: notified_process_tests.py.
"""

import os
import subprocess
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from typing import IO, Literal, override

from .readiness import Readiness


class ProxyProcess(subprocess.Popen[bytes]):
    stdin: IO[bytes] | None
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None

    def __init__(
        self,
        args: Sequence[str],
        *,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        stdin: int | None = None,
        stdout: int | None = subprocess.PIPE,
        stderr: int | None = subprocess.PIPE,
        text: Literal[False] = False,
    ) -> None:
        self._readiness: Readiness = Readiness()
        environment = dict(os.environ if env is None else env)
        environment["NOTIFY_SOCKET"] = self._readiness.address
        with ExitStack() as setup:
            _ = setup.callback(self._readiness.close)
            super().__init__(
                args,
                cwd=cwd,
                env=environment,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                text=text,
            )
            _ = setup.pop_all()

    def wait_ready(self) -> bool:
        """Wait for READY=1 or process exit, without a startup deadline."""
        if self.poll() is not None:
            return False
        notified = self._readiness.wait_for(self.pid)
        running = self.poll() is None
        return notified and running

    @override
    def poll(self) -> int | None:
        code = super().poll()
        if code is not None:
            self._readiness.close()
        return code

    @override
    def wait(self, timeout: float | None = None) -> int:
        code = super().wait(timeout=timeout)
        self._readiness.close()
        return code
