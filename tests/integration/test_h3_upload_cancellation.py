"""Process contract: aborting a forward upload must reset its H3 request."""

import asyncio
from pathlib import Path
from typing import override

from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent, StreamReset

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_protocol import H3ProtocolBase
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import managed_processes
from tests.fixtures.stream_cleanup import close_writer


async def verify_upload_cancellation(directory: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(directory))
    upstream_port = get_unique_port()
    entry_port = get_unique_port()
    resets: asyncio.Queue[StreamReset] = asyncio.Queue()

    class Peer(H3ProtocolBase):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            if isinstance(event, StreamReset):
                resets.put_nowait(event)
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    self.http.send_headers(message.stream_id, [(b":status", b"200")])
                    self.http.send_data(message.stream_id, b"ready", end_stream=False)
                    self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(cert, key)
    peer = await serve(
        "127.0.0.1", upstream_port, configuration=configuration, create_protocol=Peer
    )
    path = directory / "proxy.yaml"
    _ = path.write_text(f"""server_threads: 1
plugins:
  http_upstream:
    certificates:
      server_ca_path: {ca}
    upstreams:
    - name: relay
      addresses:
      - address: 127.0.0.1:{upstream_port}
        hostname: localhost
        http3: {{}}
listeners:
- name: main
  kind: http
  addresses: ["127.0.0.1:{entry_port}"]
services:
- name: relay
  kind: http_upstream.upstream
  args:
    upstream: relay
servers:
- name: main
  service: relay
  listeners: [main]
""")
    try:
        with managed_processes() as start:
            process = start(str(path))
            assert process.wait_ready(timeout=3)
            reader, writer = await asyncio.open_connection("127.0.0.1", entry_port)
            try:
                writer.write(
                    b"POST http://origin.test/upload HTTP/1.1\r\n"
                    + b"Host: origin.test\r\nTransfer-Encoding: chunked\r\n"
                    + b"\r\n5\r\nfirst\r\n"
                )
                await writer.drain()
                async with asyncio.timeout(2):
                    response = b""
                    while b"ready" not in response:
                        data = await reader.read(4096)
                        assert data
                        response += data
            finally:
                await close_writer(writer)
            async with asyncio.timeout(2):
                reset = await resets.get()
                assert reset.error_code == 0x10C  # H3_REQUEST_CANCELLED
    finally:
        peer.close()


def test_cancelled_forward_upload_resets_upstream_h3_request(tmp_path: Path) -> None:
    asyncio.run(verify_upload_cancellation(tmp_path))
