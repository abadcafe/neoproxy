"""Black-box contracts for asynchronous stream resource cleanup."""

import asyncio

import pytest

from .stream_cleanup import close_writer


class RecordingWriter:
    def __init__(self, failure: ConnectionResetError | BrokenPipeError | None) -> None:
        self.failure: ConnectionResetError | BrokenPipeError | None = failure
        self.events: list[str] = []

    def close(self) -> None:
        self.events.append("close")

    async def wait_closed(self) -> None:
        self.events.append("wait_closed")
        if self.failure is not None:
            # Simulate the documented network exceptions of StreamWriter.
            raise self.failure


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, ConnectionResetError(), BrokenPipeError()])
async def test_close_writer_completes_after_normal_or_peer_disconnected_close(
    failure: ConnectionResetError | BrokenPipeError | None,
) -> None:
    writer = RecordingWriter(failure)
    await close_writer(writer)
    assert writer.events == ["close", "wait_closed"]


@pytest.mark.asyncio
async def test_close_writer_preserves_task_cancellation() -> None:
    class PendingWriter:
        def __init__(self) -> None:
            self.waiting: asyncio.Event = asyncio.Event()

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            self.waiting.set()
            _ = await asyncio.Event().wait()

    writer = PendingWriter()
    task = asyncio.create_task(close_writer(writer))
    _ = await writer.waiting.wait()
    _ = task.cancel()
    done, pending = await asyncio.wait([task], timeout=1)
    assert task in done and not pending
    assert task.cancelled()
