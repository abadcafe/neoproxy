"""Tracing must preserve a response while transport reads are pending."""

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
from tests.fixtures.chain_diagnostics import record_chain
from tests.fixtures.h3_configuration import create_http3_chain_config
from tests.fixtures.h3_protocol import H3ProtocolBase
from tests.fixtures.ports import get_unique_port
from tests.fixtures.stream_cleanup import close_writer


@pytest.mark.asyncio
async def test_trace_preserves_response_with_buffered_data_and_pending_read(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    upstream, entry = get_unique_port(), get_unique_port()
    first, last = b"first-part" * 10, b"last-part" * 1000

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
                finish_timer = self.finishes.pop(event.stream_id, None)
                if finish_timer is not None:
                    finish_timer.cancel()
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    self.http.send_headers(
                        message.stream_id,
                        [
                            (b":status", b"200"),
                            (b"content-length", str(len(first) + len(last)).encode()),
                        ],
                    )
                    self.http.send_data(message.stream_id, first, end_stream=False)
                    # Headers and initial content share a datagram while
                    # the next transport read remains pending. h3-quinn
                    # 0.0.10 recv_id() unwraps None in that state. Production
                    # diagnostics must use an ID captured before receiving;
                    # the dependency itself is intentionally not patched.
                    self.transmit()

                    def finish(stream: int = message.stream_id) -> None:
                        _ = self.finishes.pop(stream)
                        self.http.send_data(stream, last, end_stream=True)
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
        with record_chain(
            {"entry": tmp_path},
            {"case": "pending-read"},
            artifact_root=tmp_path / "artifacts",
        ) as capture:
            directory = capture.directory
            process = capture.start_proxy("entry", config)
            assert process.wait_ready(timeout=3)
            reader, writer = await asyncio.open_connection("127.0.0.1", entry)
            try:
                writer.write(
                    b"GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n"
                    + b"X-Request-ID: trace-caller-id\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                async with asyncio.timeout(3):
                    headers = await reader.readuntil(b"\r\n\r\n")
                    assert headers.startswith(b"HTTP/1.1 200 "), headers
                    assert b"x-request-id: trace-caller-id" in headers.lower()
                    assert (
                        await reader.readexactly(len(first) + len(last)) == first + last
                    )
                assert process.poll() is None
            finally:
                await close_writer(writer)
    finally:
        server.close()
    assert process.returncode == 0
    logs = "".join(
        path.read_text() for path in (directory / "entry/logs").glob("neoproxy.log*")
    )
    assert "H3 response content received" in logs and "stream_id=" in logs
    assert "request_id=trace-caller-id" in logs
    # A Content-Length encoder can finish after its last byte without
    # polling the source for EOF. Compare observed bytes to actual content.
    sizes = [
        line.partition("bytes=")[2].split()[0]
        for line in logs.splitlines()
        if "H3 response content received" in line
    ]
    assert sum(int(size) for size in sizes) == len(first) + len(last)
