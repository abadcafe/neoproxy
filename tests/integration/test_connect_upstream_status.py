"""CONNECT status handling, including a recorded Hyper 1.6.0 limitation.

Only wire interfaces are used. HTTP(S) peers and an H3 peer return selected
statuses, send data with the successful response, and echo tunnel bytes.
"""

import asyncio
import ssl
from pathlib import Path
from typing import Literal, override

import pytest
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer

type UpstreamKind = Literal["http", "https", "http3"]

STATUSES = (200, 201, 204, 299, 300, 407, 502)
GREETING = b"upstream-first\x00\xff"
PAYLOADS = (b"client-first\x00\xff", b"second-round\r\n\r\n")


async def _check_entry(
    directory: Path, upstream: int, kind: UpstreamKind, ca: str, status: int
) -> None:
    entry = get_unique_port()
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
        {kind}: {{}}
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
        assert wait_for_proxy("127.0.0.1", entry, timeout=3, proc=process)
        reader, writer = await asyncio.open_connection("127.0.0.1", entry)
        try:
            async with asyncio.timeout(3):
                writer.write(
                    b"CONNECT target.example:443 HTTP/1.1\r\n"
                    + b"Host: target.example:443\r\n\r\n"
                )
                await writer.drain()
                headers = await reader.readuntil(b"\r\n\r\n")
                actual = int(headers.split(b"\r\n", 1)[0].split()[1])
                if kind in ("http", "https") and status == 204:
                    # Third-party defect, not an accepted protocol behavior:
                    # Hyper 1.6.0 proto/h1/role.rs Client::decoder returns
                    # (ZERO, false) for 204 before checking CONNECT + 2xx.
                    # Consequently OnUpgrade fails and this proxy reports 502.
                    # Record the actual failed tunnel, without modifying Hyper,
                    # skip/xfail, or weakening the normal successful cases.
                    assert actual == 502, headers
                    assert b"error=connection_terminated" in headers
                elif 200 <= status < 300:
                    # This proxy generates its own successful CONNECT response.
                    assert actual == 200, headers
                    # Preserve bytes already buffered when the upgrade occurs.
                    assert await reader.readexactly(len(GREETING)) == GREETING
                    for payload in PAYLOADS:
                        writer.write(payload)
                        await writer.drain()
                        assert await reader.readexactly(len(payload)) == payload
                else:
                    expected = 502 if status == 407 else status
                    assert actual == expected, headers
                    assert f"received-status={status}".encode() in headers
        finally:
            await close_writer(writer)
    finally:
        terminate_process(process, force=True)


async def _check_http_upstream(
    directory: Path, kind: Literal["http", "https"], status: int
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(directory))
    tls: ssl.SSLContext | None = None
    if kind == "https":
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
    upstream = get_unique_port()
    received: asyncio.Queue[bytes] = asyncio.Queue()

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            async with asyncio.timeout(5):
                received.put_nowait(await reader.readuntil(b"\r\n\r\n"))
                writer.write(f"HTTP/1.1 {status} Test\r\n\r\n".encode())
                if 200 <= status < 300:
                    writer.write(GREETING)
                    await writer.drain()
                    while data := await reader.read(4096):
                        writer.write(data)
                        await writer.drain()
                else:
                    await writer.drain()
        finally:
            await close_writer(writer)

    # TaskGroup propagates peer failures instead of leaving assertions in an
    # unobserved background task. The client closes every accepted tunnel.
    async with asyncio.TaskGroup() as connections:

        def connected(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            _ = connections.create_task(handle(reader, writer))

        server = await asyncio.start_server(connected, "127.0.0.1", upstream, ssl=tls)
        async with server:
            await _check_entry(directory, upstream, kind, ca, status)
            headers = received.get_nowait()
            assert headers.startswith(b"CONNECT target.example:443 HTTP/1.1\r\n")


@pytest.mark.parametrize("status", [200, 201, 299, 300, 407, 502])
@pytest.mark.parametrize("kind", ["http", "https"])
def test_connect_http_upstream_status(
    tmp_path: Path, kind: Literal["http", "https"], status: int
) -> None:
    asyncio.run(_check_http_upstream(tmp_path, kind, status))


@pytest.mark.parametrize("kind", ["http", "https"])
def test_hyper_dependency_connect_204_fails_to_upgrade(
    tmp_path: Path, kind: Literal["http", "https"]
) -> None:
    """RFC 9110 §9.3.6 requires success; Hyper 1.6.0 does not expose the I/O."""
    asyncio.run(_check_http_upstream(tmp_path, kind, 204))


async def _check_h3_upstream(directory: Path, status: int) -> None:
    cert, key, ca, _ = generate_test_certificates(str(directory))
    upstream = get_unique_port()
    received: asyncio.Queue[list[tuple[bytes, bytes]]] = asyncio.Queue()

    class ConnectPeer(QuicConnectionProtocol):
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
                    # h3 0.0.8 adds :scheme/:path to classic CONNECT. This peer
                    # accepts that known dependency defect so this test isolates
                    # response-status handling. test_dependency_h3.py separately
                    # records rejection by a strict peer; no dependency is patched.
                    self.http.send_headers(
                        message.stream_id,
                        [(b":status", str(status).encode())],
                        end_stream=not 200 <= status < 300,
                    )
                    if 200 <= status < 300:
                        self.http.send_data(
                            message.stream_id, GREETING, end_stream=False
                        )
                elif isinstance(message, DataReceived) and message.data:
                    self.http.send_data(
                        message.stream_id, message.data, end_stream=message.stream_ended
                    )
            self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(cert, key)
    server = await serve(
        "127.0.0.1", upstream, configuration=configuration, create_protocol=ConnectPeer
    )
    try:
        await _check_entry(directory, upstream, "http3", ca, status)
        fields = dict(received.get_nowait())
        assert fields[b":method"] == b"CONNECT"
        assert fields[b":authority"] == b"target.example:443"
    finally:
        server.close()


@pytest.mark.parametrize("status", STATUSES)
def test_connect_h3_upstream_status(tmp_path: Path, status: int) -> None:
    asyncio.run(_check_h3_upstream(tmp_path, status))
