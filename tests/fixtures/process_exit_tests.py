"""Native exit descriptor contracts, run unchanged on Linux and macOS."""

import selectors
import subprocess
import sys

from tests.fixtures.process_exit import ExitNotification


def test_exit_notification_is_selectable_after_the_child_exits() -> None:
    with subprocess.Popen(
        [sys.executable, "-c", "import sys; _ = sys.stdin.read()"],
        stdin=subprocess.PIPE,
    ) as child:
        with ExitNotification(child.pid) as exited:
            with selectors.DefaultSelector() as events:
                _ = events.register(exited, selectors.EVENT_READ)
                assert not events.select(timeout=0)
                assert child.stdin is not None
                child.stdin.close()
                assert events.select(timeout=2)
        assert child.wait(timeout=2) == 0
