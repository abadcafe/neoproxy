"""module: h3_lifecycle; responsibility: observe H3 lifecycle on the wire.
Public operations: LifecycleClient request, event, completion and GOAWAY methods.
Data entities: LifecycleClient, StreamEvent.
Tests: integration/test_http3_shutdown.py against a real proxy process.
"""

import asyncio
from typing import override

from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    ConnectionTerminated,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)

from tests.fixtures.http3_client import H3ProtocolBase

type StreamEvent = H3Event | StreamReset | ConnectionTerminated | StreamDataReceived


def _varint(data: bytearray, offset: int) -> tuple[int, int] | None:
    if offset >= len(data):
        return None
    length = 1 << (data[offset] >> 6)
    if offset + length > len(data):
        return None
    value = int.from_bytes(data[offset : offset + length])
    return value & ((1 << (length * 8 - 2)) - 1), offset + length


class LifecycleClient(H3ProtocolBase):
    def __init__(
        self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
    ) -> None:
        super().__init__(quic, stream_handler)
        self.http: H3Connection = H3Connection(quic)
        self.events: dict[int, asyncio.Queue[StreamEvent]] = {}
        self.goaway_ids: list[int] = []
        self.closed: asyncio.Event = asyncio.Event()
        self.changed: asyncio.Event = asyncio.Event()
        self.settings_received: asyncio.Event = asyncio.Event()
        self._buffers: dict[int, bytearray] = {}
        self._ended: set[int] = set()

    @override
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.closed.set()
            self.changed.set()
            for queue in self.events.values():
                queue.put_nowait(event)
        elif isinstance(event, StreamReset):
            self.events.setdefault(event.stream_id, asyncio.Queue()).put_nowait(event)
        elif isinstance(event, StreamDataReceived) and event.stream_id % 4 == 3:
            buffer = self._buffers.setdefault(event.stream_id, bytearray())
            buffer.extend(event.data)
            self._read_control(buffer)
        for message in self.http.handle_event(event):
            if isinstance(message, (HeadersReceived, DataReceived)):
                self.events.setdefault(message.stream_id, asyncio.Queue()).put_nowait(
                    message
                )
        if (
            isinstance(event, StreamDataReceived)
            and event.end_stream
            and event.stream_id % 4 == 0
        ):
            # aioquic can omit the terminal H3 event when a GREASE
            # frame precedes FIN. Observe the actual QUIC FIN, after
            # queueing all decoded H3 data/trailers from that packet.
            # Never infer completion from a timeout or a connection close.
            self.events.setdefault(event.stream_id, asyncio.Queue()).put_nowait(event)

    def _read_control(self, buffer: bytearray) -> None:
        stream_type = _varint(buffer, 0)
        if stream_type is None or stream_type[0] != 0:
            return
        offset = stream_type[1]
        while True:
            kind = _varint(buffer, offset)
            if kind is None:
                break
            length = _varint(buffer, kind[1])
            if length is None or length[1] + length[0] > len(buffer):
                break
            if kind[0] == 7:
                identifier = _varint(buffer, length[1])
                assert identifier is not None
                self.goaway_ids.append(identifier[0])
                self.changed.set()
            elif kind[0] == 4:
                self.settings_received.set()
            offset = length[1] + length[0]
        # Preserve the one-byte control-stream type and an incomplete frame.
        del buffer[1:offset]

    def request(
        self, method: bytes, authority: bytes = b"echo.test", scheme: bytes = b"https"
    ) -> int:
        stream = self.quic_connection.get_next_available_stream_id()
        self.events[stream] = asyncio.Queue()
        headers = [(b":method", method), (b":authority", authority)]
        if method != b"CONNECT":
            headers.extend([(b":scheme", scheme), (b":path", b"/")])
        self.http.send_headers(stream, headers)
        self.transmit()
        return stream

    def incomplete_request(self) -> int:
        stream = self.quic_connection.get_next_available_stream_id()
        self.events[stream] = asyncio.Queue()
        self.quic_connection.send_stream_data(stream, b"\x01", end_stream=False)
        self.transmit()
        return stream

    async def goaway(self) -> int:
        async with asyncio.timeout(2):
            while not self.goaway_ids:
                assert not self.closed.is_set(), "connection closed before GOAWAY"
                _ = await self.changed.wait()
                self.changed.clear()
        return self.goaway_ids[-1]

    async def next_event(self, stream: int) -> StreamEvent:
        return await asyncio.wait_for(self.events[stream].get(), timeout=6)

    async def read_data(self, stream: int, expected: bytes) -> None:
        received = b""
        while len(received) < len(expected):
            event = await self.next_event(stream)
            assert not isinstance(event, (ConnectionTerminated, StreamReset)), event
            if isinstance(event, HeadersReceived):
                assert (b":status", b"200") in event.headers, event.headers
            elif isinstance(event, DataReceived):
                received += event.data
                if event.stream_ended:
                    self._ended.add(stream)
        assert received == expected

    async def read_end(self, stream: int) -> list[tuple[bytes, bytes]]:
        if stream in self._ended:
            return []
        trailers: list[tuple[bytes, bytes]] = []
        while True:
            event = await self.next_event(stream)
            assert not isinstance(event, (ConnectionTerminated, StreamReset)), event
            if isinstance(event, HeadersReceived):
                if not any(name.startswith(b":") for name, _ in event.headers):
                    trailers = event.headers
                if event.stream_ended:
                    return trailers
            if isinstance(event, DataReceived) and event.stream_ended:
                return trailers
            if isinstance(event, StreamDataReceived) and event.end_stream:
                return trailers
