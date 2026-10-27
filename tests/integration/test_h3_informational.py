"""An upstream H3 informational section must not replace the final response."""

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
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import managed_processes
from tests.fixtures.stream_cleanup import close_writer


async def final_response(directory: Path, method: Literal["GET", "CONNECT"]) -> None:
    certificate, key, ca, _ = generate_test_certificates(str(directory))
    upstream = get_unique_port()
    entry = get_unique_port()

    class InformationalPeer(H3ProtocolBase):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    # aioquic's send_headers treats a second header section as
                    # trailers even after 103. Emit valid frames through public
                    # QUIC/QPACK APIs; do not patch the dependency's state.
                    encoder = Encoder()
                    _, informational = encoder.encode(
                        message.stream_id, [(b":status", b"103")]
                    )
                    _, final = encoder.encode(message.stream_id, [(b":status", b"200")])
                    self.quic_connection.send_stream_data(
                        message.stream_id,
                        encode_frame(FrameType.HEADERS, informational)
                        + encode_frame(FrameType.HEADERS, final)
                        + encode_frame(FrameType.DATA, b"OK"),
                        end_stream=True,
                    )
                    self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(certificate, key)
    server = await serve(
        "127.0.0.1",
        upstream,
        configuration=configuration,
        create_protocol=InformationalPeer,
    )
    config = directory / "entry.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  http_upstream:
    certificates: {{server_ca_path: {ca}}}
    upstreams:
    - name: relay
      addresses:
      - address: 127.0.0.1:{upstream}
        hostname: localhost
        address_protocol: http3
listeners:
- name: main
  kind: http
  addresses: ["127.0.0.1:{entry}"]
services:
- name: relay
  kind: http_upstream.upstream
  args: {{upstream: relay}}
servers:
- name: relay
  service: relay
  listeners: [main]
""")
    try:
        with managed_processes() as start:
            process = start(str(config))
            assert process.wait_ready(timeout=3)
            reader, writer = await asyncio.open_connection("127.0.0.1", entry)
            try:
                target = (
                    "example.test:443"
                    if method == "CONNECT"
                    else "http://example.test/"
                )
                writer.write(
                    (
                        f"{method} {target} HTTP/1.1\r\n"
                        + "Host: example.test\r\nConnection: close\r\n\r\n"
                    ).encode()
                )
                await writer.drain()
                async with asyncio.timeout(3):
                    headers = await reader.readuntil(b"\r\n\r\n")
                    assert b" 200 " in headers.split(b"\r\n", 1)[0], headers
                    payload = await reader.read()
                    assert b"OK" in payload, payload
            finally:
                await close_writer(writer)
    finally:
        server.close()


@pytest.mark.parametrize("method", ["GET", "CONNECT"])
def test_h3_upstream_waits_for_final_response(
    tmp_path: Path, method: Literal["GET", "CONNECT"]
) -> None:
    asyncio.run(final_response(tmp_path, method))
