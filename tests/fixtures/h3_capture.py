"""module: h3_capture; responsibility: serve controlled H3 response streams.
Public operations: capture_peer, CapturePeer, RESPONSE_BODY.
Data entities: CapturePeer. Tests: h3_request_tests.py, http3_client_tests.py.
"""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import override

from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.ports import get_unique_port

RESPONSE_BODY = b"received request\x00\xff"


@dataclass(frozen=True)
class CapturePeer:
    port: int
    ca_path: str
    received: asyncio.Queue[HeadersReceived]


@asynccontextmanager
async def capture_peer(
    directory: Path, delay: float = 0
) -> AsyncGenerator[CapturePeer, None]:
    certificate, key, ca, _ = generate_test_certificates(str(directory))
    received: asyncio.Queue[HeadersReceived] = asyncio.Queue()

    class CaptureProtocol(QuicConnectionProtocol):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    received.put_nowait(message)
                    self.http.send_headers(
                        message.stream_id,
                        [
                            (b":status", b"201"),
                            (b"x-peer", b"capture-peer"),
                            (b"content-length", str(len(RESPONSE_BODY)).encode()),
                        ],
                    )
                    if delay:
                        self.http.send_data(
                            message.stream_id, RESPONSE_BODY[:3], end_stream=False
                        )

                        def finish(stream_id: int = message.stream_id) -> None:
                            self.http.send_data(
                                stream_id, RESPONSE_BODY[3:], end_stream=True
                            )
                            self.transmit()

                        _ = asyncio.get_running_loop().call_later(delay, finish)
                    else:
                        self.http.send_data(
                            message.stream_id, RESPONSE_BODY, end_stream=True
                        )
                    self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(certificate, key)
    port = get_unique_port()
    server = await serve(
        "127.0.0.1", port, configuration=configuration, create_protocol=CaptureProtocol
    )
    try:
        yield CapturePeer(port, ca, received)
    finally:
        server.close()
