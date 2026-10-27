"""module: process_exit; responsibility: expose process exit as a kernel event.
Public operations: ExitNotification.{fileno,close}, context manager.
Data entities: ExitNotification. Tests: process_exit_tests.py.
"""

import platform
from contextlib import ExitStack
from types import TracebackType
from typing import Self

from . import linux, macos


class ExitNotification:
    def __init__(self, pid: int) -> None:
        with ExitStack() as setup:
            system = platform.system()
            self._fd: int
            if system == "Linux":
                self._fd = linux.register(pid, setup)
            elif system == "Darwin":
                self._fd = macos.register(pid, setup)
            else:
                raise NotImplementedError(
                    f"process notifications: unsupported OS {system}"
                )
            self._resources: ExitStack = setup.pop_all()

    def fileno(self) -> int:
        return self._fd

    def close(self) -> None:
        self._resources.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
