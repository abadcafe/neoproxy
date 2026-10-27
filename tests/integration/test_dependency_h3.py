"""Executable failure case for the unmodified h3 dependency's CONNECT encoder."""

import asyncio
from pathlib import Path
from typing import override

from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_protocol import H3ProtocolBase
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer


async def verify_dependency_failure(directory: Path) -> None:
    certificate, key, ca, _ = generate_test_certificates(str(directory))
    upstream = get_unique_port()
    entry = get_unique_port()
    received: asyncio.Queue[list[tuple[bytes, bytes]]] = asyncio.Queue()

    class StrictConnectServer(H3ProtocolBase):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    received.put_nowait(message.headers)
                    # RFC 9114 §4.4 forbids :scheme and :path in classic CONNECT.
                    # h3 0.0.8's Pseudo::request unconditionally adds both, even
                    # for an authority-only URI. A strict peer rejects it. The
                    # dependency is deliberately not patched or monkey-patched.
                    # This test records the actual wire failure without skip,
                    # xfail, or weakening the normal successful tunnel tests.
                    self.http.send_headers(
                        message.stream_id, [(b":status", b"400")], end_stream=True
                    )
                    self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(certificate, key)
    server = await serve(
        "127.0.0.1",
        upstream,
        configuration=configuration,
        create_protocol=StrictConnectServer,
    )
    config = directory / "entry.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  http_upstream:
    certificates:
      server_ca_path: {ca}
    upstreams:
    - name: relay
      addresses:
      - address: 127.0.0.1:{upstream}
        hostname: localhost
        http3: {{}}
listeners:
- name: main
  kind: http
  addresses: ["127.0.0.1:{entry}"]
services:
- name: relay
  kind: http_upstream.upstream
  args:
    upstream: relay
servers:
- name: relay
  service: relay
  listeners: [main]
""")
    process = start_proxy(str(config))
    try:
        assert process.wait_ready(timeout=3)
        reader, writer = await asyncio.open_connection("127.0.0.1", entry)
        try:
            writer.write(
                b"CONNECT example.test:443 HTTP/1.1\r\n"
                + b"Host: example.test:443\r\n\r\n"
            )
            await writer.drain()
            async with asyncio.timeout(3):
                response = await reader.readuntil(b"\r\n\r\n")
                fields = dict(await received.get())
            assert fields[b":method"] == b"CONNECT"
            assert fields[b":authority"] == b"example.test:443"
            assert b":scheme" in fields and b":path" in fields
            assert b"400" in response.split(b"\r\n", 1)[0]
        finally:
            await close_writer(writer)
    finally:
        server.close()
        terminate_process(process, timeout=5, force=True)


def test_h3_dependency_classic_connect_is_rejected_by_strict_peer(
    tmp_path: Path,
) -> None:
    asyncio.run(verify_dependency_failure(tmp_path))
