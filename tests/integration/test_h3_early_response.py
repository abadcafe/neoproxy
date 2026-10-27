"""An upstream may stop request upload while returning a complete final response."""

import asyncio
from pathlib import Path
from typing import override

import pytest
from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent, StopSendingReceived

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_configuration import create_http3_chain_config
from tests.fixtures.h3_protocol import H3ProtocolBase
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import managed_processes
from tests.fixtures.stream_cleanup import close_writer


@pytest.mark.asyncio
async def test_final_response_survives_peer_stopping_upload(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    upstream, entry = get_unique_port(), get_unique_port()

    class Peer(H3ProtocolBase):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)
            self.finishes: dict[int, asyncio.TimerHandle] = {}

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            if isinstance(event, StopSendingReceived):
                pending = self.finishes.pop(event.stream_id, None)
                if pending is not None:
                    pending.cancel()
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    self.http.send_headers(
                        message.stream_id,
                        [(b":status", b"413"), (b"content-length", b"6")],
                    )
                    # RFC 9114 §4.1: stopping an unwanted upload with
                    # H3_NO_ERROR does not cancel the response direction.
                    self.quic_connection.stop_stream(message.stream_id, 0x100)
                    self.transmit()

                    def finish(stream: int = message.stream_id) -> None:
                        _ = self.finishes.pop(stream)
                        self.http.send_data(stream, b"denied", end_stream=True)
                        self.transmit()

                    self.finishes[message.stream_id] = (
                        asyncio.get_running_loop().call_later(0.15, finish)
                    )

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(cert, key)
    server = await serve(
        "127.0.0.1", upstream, configuration=configuration, create_protocol=Peer
    )
    config = create_http3_chain_config(
        entry, [("127.0.0.1", upstream, 1)], ca, str(tmp_path)
    )
    try:
        with managed_processes() as start:
            process = start(config)
            assert process.wait_ready(timeout=3)
            reader, writer = await asyncio.open_connection("127.0.0.1", entry)
            try:
                writer.write(
                    b"POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n"
                    + b"Connection: close\r\nTransfer-Encoding: chunked\r\n"
                    + b"\r\n5\r\nfirst\r\n"
                )
                await writer.drain()
                async with asyncio.timeout(3):
                    headers = await reader.readuntil(b"\r\n\r\n")
                    assert headers.startswith(b"HTTP/1.1 413 "), headers
                    writer.write(b"6\r\nsecond\r\n0\r\n\r\n")
                    await writer.drain()
                    assert await reader.read() == b"denied"
            finally:
                await close_writer(writer)
    finally:
        server.close()
