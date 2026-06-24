import asyncio
from collections.abc import Callable

from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

type QuicStreamHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], None]

class QuicConnectionProtocol:
    _quic: QuicConnection
    _stream_readers: dict[int, asyncio.StreamReader]

    def __init__(self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None) -> None: ...
    async def wait_connected(self) -> None: ...
    def transmit(self) -> None: ...
    def quic_event_received(self, event: QuicEvent) -> None: ...
