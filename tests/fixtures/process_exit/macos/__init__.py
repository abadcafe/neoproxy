"""module: process_exit.macos; responsibility: register a kqueue exit event.
Public operations: register. Data entities: none.
Tests: process_exit_tests.py through ExitNotification on macOS.
"""

import select
from contextlib import ExitStack


def register(pid: int, resources: ExitStack) -> int:
    queue = select.kqueue()
    _ = resources.callback(queue.close)
    event = select.kevent(
        pid,
        filter=select.KQ_FILTER_PROC,
        flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
        fflags=select.KQ_NOTE_EXIT,
    )
    _ = queue.control([event], 0, 0)
    return queue.fileno()
