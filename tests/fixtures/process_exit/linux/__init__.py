"""module: process_exit.linux; responsibility: register a pidfd exit event.
Public operations: register. Data entities: none.
Tests: process_exit_tests.py through ExitNotification.
"""

import os
from contextlib import ExitStack


def register(pid: int, resources: ExitStack) -> int:
    descriptor = os.pidfd_open(pid)
    _ = resources.callback(os.close, descriptor)
    return descriptor
