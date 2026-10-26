"""module: h3_protocol; responsibility: observe complete H3 stream events.
Public operations: H3ProtocolBase, EventProtocol stream operations.
Data entities: H3ProtocolBase, EventProtocol, StreamEvent.
Tests: http3_client_tests.py and process wire contracts.
"""

import asyncio
from typing import final, override

from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)

type StreamEvent = (
    HeadersReceived
    | DataReceived
    | StreamDataReceived
    | StreamReset
    | ConnectionTerminated
)


class H3ProtocolBase(QuicConnectionProtocol):
    """Expose QUIC and H3 state through the fixture's public contract."""

    def __init__(
        self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
    ) -> None:
        super().__init__(quic, stream_handler)
        self._h3: H3Connection | None = None

    @property
    def quic_connection(self) -> QuicConnection:
        return self._quic

    @property
    def h3_connection(self) -> H3Connection | None:
        return self._h3

    @h3_connection.setter
    def h3_connection(self, value: H3Connection) -> None:
        self._h3 = value


@final
class EventProtocol(H3ProtocolBase):
    def __init__(
        self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
    ) -> None:
        super().__init__(quic, stream_handler)
        self.h3_connection = H3Connection(quic)
        self._events: dict[int, asyncio.Queue[StreamEvent]] = {}
        self._terminated: ConnectionTerminated | None = None

    @override
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self._terminated = event
            for queue in self._events.values():
                queue.put_nowait(event)
        elif isinstance(event, StreamReset):
            self._events.setdefault(event.stream_id, asyncio.Queue()).put_nowait(event)
        http = self.h3_connection
        assert http is not None
        for message in http.handle_event(event):
            if isinstance(message, (HeadersReceived, DataReceived)):
                self._events.setdefault(message.stream_id, asyncio.Queue()).put_nowait(
                    message
                )
        if (
            isinstance(event, StreamDataReceived)
            and event.end_stream
            and event.stream_id % 4 == 0
        ):
            # aioquic can omit stream_ended on the last H3 event if GREASE
            # consumes the end of the QUIC packet. The actual FIN is the
            # completion signal; a quiet network interval is never EOF.
            self._events.setdefault(event.stream_id, asyncio.Queue()).put_nowait(event)

    def request(self, headers: list[tuple[bytes, bytes]], end_stream: bool) -> int:
        http = self.h3_connection
        assert http is not None
        stream = self.quic_connection.get_next_available_stream_id()
        self._events[stream] = asyncio.Queue()
        http.send_headers(stream, headers, end_stream=end_stream)
        self.transmit()
        return stream

    def send_data(self, stream: int, data: bytes, end_stream: bool) -> None:
        http = self.h3_connection
        assert http is not None
        http.send_data(stream, data, end_stream=end_stream)
        self.transmit()

    async def next_event(self, stream: int) -> StreamEvent:
        queue = self._events[stream]
        if queue.empty() and self._terminated is not None:
            return self._terminated
        return await queue.get()
