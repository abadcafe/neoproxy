"""module: stream_cleanup; responsibility: release asynchronous stream writers.
Public operations: ClosingStream, close_writer. Data entities: ClosingStream.
Tests: stream_cleanup_tests.py and process transport contracts.
"""

from typing import Protocol


class ClosingStream(Protocol):
    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...


async def close_writer(writer: ClosingStream) -> None:
    """Release resources after an exchange, including an already disconnected peer.

    Payload and EOF assertions belong to the exchange before cleanup. Only normal
    peer disconnects from the close waiter are handled here; cancellation and
    programming failures propagate.
    """
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionResetError, BrokenPipeError:
        pass
