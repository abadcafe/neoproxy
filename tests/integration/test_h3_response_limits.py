"""Upstream H3 decoded headers, informational sections and trailers are bounded."""

import asyncio
from pathlib import Path
from typing import Literal, override

import pytest
from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import FrameType, H3Connection, encode_frame
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent
from pylsqpack import Encoder

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_protocol import H3ProtocolBase
from tests.fixtures.http_policy_scenario import configuration
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.stream_cleanup import close_writer

type Section = Literal["initial", "informational", "trailers", "size"]


@pytest.mark.asyncio
@pytest.mark.parametrize("section", ["initial", "informational", "trailers", "size"])
async def test_h3_response_sections_enforce_pool_limits(
    tmp_path: Path, section: Section
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    port = get_unique_port()
    timers: list[asyncio.TimerHandle] = []

    class Peer(H3ProtocolBase):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            for message in self.http.handle_event(event):
                if not isinstance(message, HeadersReceived):
                    continue
                encoder = Encoder()
                fields: list[tuple[bytes, bytes]] = [(b"x-test", b"a")] * 3
                if section == "size":
                    fields = [(b"x-large", b"a" * 2000)]
                status = b"103" if section == "informational" else b"200"
                if section != "trailers":
                    _, block = encoder.encode(
                        message.stream_id, [(b":status", status), *fields]
                    )
                    wire = encode_frame(FrameType.HEADERS, block)
                else:
                    _, initial = encoder.encode(
                        message.stream_id, [(b":status", b"200")]
                    )
                    _, trailers = encoder.encode(message.stream_id, fields)
                    wire = encode_frame(FrameType.HEADERS, initial) + encode_frame(
                        FrameType.DATA, b"payload"
                    )

                    def finish(
                        stream: int = message.stream_id, block: bytes = trailers
                    ) -> None:
                        self.quic_connection.send_stream_data(
                            stream,
                            encode_frame(FrameType.HEADERS, block),
                            end_stream=True,
                        )
                        self.transmit()

                    timers.append(asyncio.get_running_loop().call_later(0.2, finish))
                self.quic_connection.send_stream_data(
                    message.stream_id, wire, end_stream=section != "trailers"
                )
                self.transmit()

    quic = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    quic.load_cert_chain(cert, key)
    peer = await serve("127.0.0.1", port, configuration=quic, create_protocol=Peer)
    config = configuration({}, {})
    config["plugins"] = {
        "upstream": {
            "connection_pools": [
                {
                    "name": "default",
                    "max_response_headers": 100 if section == "size" else 2,
                    "max_response_header_size": "1KiB"
                    if section == "size"
                    else "32KiB",
                    "certificates": {"server_ca_path": ca},
                }
            ],
            "upstreams": [
                {
                    "name": "main",
                    "addresses": [
                        {
                            "address": f"127.0.0.1:{port}",
                            "hostname": "localhost",
                            "address_protocol": "http3",
                        }
                    ],
                }
            ],
        }
    }
    try:
        with running_proxy(tmp_path / "proxy", config) as proxy:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
            try:
                writer.write(
                    b"GET http://target.test/ HTTP/1.1\r\n"
                    + b"Host: target.test\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                async with asyncio.timeout(5):
                    response = await reader.read()
                if section == "trailers":
                    assert b" 200 " in response.split(b"\r\n")[0]
                    assert not response.endswith(b"0\r\n\r\n")
                else:
                    assert b" 502 " in response.split(b"\r\n")[0], response
            finally:
                await close_writer(writer)
    finally:
        for timer in timers:
            timer.cancel()
        peer.close()
