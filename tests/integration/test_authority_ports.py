"""Wire regressions for accepting empty ports and normalizing forwarded targets."""

import asyncio
import socket
import ssl
from contextlib import ExitStack
from pathlib import Path
from typing import Literal, override

import pytest
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_request import perform_h3_request_with_custom_authority
from tests.fixtures.http_configuration import create_test_config
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import ProcessFactory, start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer


async def _forward_request(
    directory: Path,
    upstream: int,
    kind: Literal["http", "https", "http3"],
    ca: str,
    host: str,
) -> None:
    entry = get_unique_port()
    config = directory / "entry.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  upstream:
    connection_pools:
      - name: default
        certificates:
          server_ca_path: {ca}
    upstreams:
    - name: relay
      addresses:
      - address: 127.0.0.1:{upstream}
        hostname: localhost
        address_protocol: {kind}
listeners:
- name: main
  kind: http
  addresses: ["127.0.0.1:{entry}"]
services:
- name: relay
  kind: upstream.upstream
  upstream: relay
servers:
- name: relay
  service: relay
  listeners: [main]
""")
    process = start_proxy(str(config))
    try:
        assert process.wait_ready()
        reader, writer = await asyncio.open_connection("127.0.0.1", entry)
        try:
            async with asyncio.timeout(3):
                writer.write(
                    (
                        f"GET http://{host}:/path?q=a:b HTTP/1.1\r\n"
                        + f"Host: {host}:\r\n"
                    ).encode()
                    + b"Connection: close\r\n\r\n"
                )
                await writer.drain()
                headers = await reader.readuntil(b"\r\n\r\n")
                assert b" 200 " in headers.split(b"\r\n", 1)[0], headers
                # Both peers send a two-byte body with a fixed Content-Length.
                assert await reader.readexactly(2) == b"OK"
        finally:
            await close_writer(writer)
    finally:
        terminate_process(process, force=True)


async def _tcp_forward(
    directory: Path, kind: Literal["http", "https"], host: str
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(directory))
    tls: ssl.SSLContext | None = None
    if kind == "https":
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
    upstream = get_unique_port()
    requests: asyncio.Queue[bytes] = asyncio.Queue()

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            async with asyncio.timeout(3):
                requests.put_nowait(await reader.readuntil(b"\r\n\r\n"))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                await writer.drain()
        finally:
            await close_writer(writer)

    async with asyncio.TaskGroup() as peers:

        def connected(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            _ = peers.create_task(handle(reader, writer))

        server = await asyncio.start_server(connected, "127.0.0.1", upstream, ssl=tls)
        async with server:
            await _forward_request(directory, upstream, kind, ca, host)
            request = requests.get_nowait()
            assert request.startswith(
                f"GET http://{host}/path?q=a:b HTTP/1.1\r\n".encode()
            )
            headers = dict(
                line.split(b":", 1)
                for line in request.split(b"\r\n")[1:]
                if b":" in line
            )
            assert {name.lower(): value.strip() for name, value in headers.items()}[
                b"host"
            ] == host.encode()


@pytest.mark.parametrize("kind", ["http", "https"])
@pytest.mark.parametrize("host", ["example.test", "[::1]"])
def test_forward_http_normalizes_empty_port(
    tmp_path: Path, kind: Literal["http", "https"], host: str
) -> None:
    asyncio.run(_tcp_forward(tmp_path, kind, host))


async def _h3_forward(directory: Path, host: str) -> None:
    cert, key, ca, _ = generate_test_certificates(str(directory))
    upstream = get_unique_port()
    requests: asyncio.Queue[list[tuple[bytes, bytes]]] = asyncio.Queue()

    class ForwardPeer(QuicConnectionProtocol):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    requests.put_nowait(message.headers)
                    self.http.send_headers(
                        message.stream_id,
                        [(b":status", b"200"), (b"content-length", b"2")],
                    )
                    self.http.send_data(message.stream_id, b"OK", end_stream=True)
                    self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(cert, key)
    server = await serve(
        "127.0.0.1", upstream, configuration=configuration, create_protocol=ForwardPeer
    )
    try:
        await _forward_request(directory, upstream, "http3", ca, host)
        headers = dict(requests.get_nowait())
        assert headers[b":authority"] == host.encode()
        assert headers[b"host"] == host.encode()
        assert headers[b":path"] == b"/path?q=a:b"
    finally:
        server.close()


@pytest.mark.parametrize("host", ["example.test", "[::1]"])
def test_forward_h3_normalizes_empty_port(tmp_path: Path, host: str) -> None:
    asyncio.run(_h3_forward(tmp_path, host))


def _echo_config(
    directory: Path, port: int, kind: Literal["http", "https", "http3"]
) -> Path:
    cert, key, _, _ = generate_test_certificates(str(directory))
    config = directory / "echo.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  echo: {{}}
listeners:
- name: main
  kind: {kind}
  addresses: ["127.0.0.1:{port}"]
services:
- name: echo
  kind: echo.echo
servers:
- name: echo
  service: echo
  listeners: [main]
  certificates:
  - cert_path: {cert}
    key_path: {key}
""")
    return config


@pytest.mark.parametrize("kind", ["http", "https"])
def test_listener_http_accepts_empty_port_and_rejects_invalid_authority(
    tmp_path: Path, proxy_process: ProcessFactory, kind: Literal["http", "https"]
) -> None:
    port = get_unique_port()
    process = proxy_process(str(_echo_config(tmp_path, port, kind)))
    assert process.wait_ready()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    for target, host, expected in [
        ("http://example.test:/path", "example.test", 200),
        ("https://example.test:/path", "example.test:", 200),
        ("/path", "example.test:", 200),
        ("http://example.test:abc/path", "example.test", 400),
        ("http://example.test:65536/path", "example.test", 400),
        ("http://user@example.test/path", "example.test", 400),
        ("/path", "example.test:abc", 400),
    ]:
        with ExitStack() as connections:
            conn = connections.enter_context(
                socket.create_connection(("127.0.0.1", port), timeout=3)
            )
            if kind == "https":
                conn = connections.enter_context(
                    context.wrap_socket(conn, server_hostname="localhost")
                )
            conn.sendall(
                (
                    f"GET {target} HTTP/1.1\r\nHost: {host}\r\n"
                    + "Connection: close\r\n\r\n"
                ).encode()
            )
            status = conn.recv(4096).split(b"\r\n", 1)[0].split()[1]
            assert int(status) == expected, (target, host, status)


def test_listener_h3_accepts_empty_port_and_rejects_invalid_authority(
    tmp_path: Path, proxy_process: ProcessFactory
) -> None:
    port = get_unique_port()
    process = proxy_process(str(_echo_config(tmp_path, port, "http3")))
    assert process.wait_ready()
    for authority, expected in [
        ("example.test:", 200),
        ("[::1]:", 200),
        ("example.test:abc", 400),
        ("example.test:65536", 400),
        ("user@example.test", 400),
    ]:
        response = asyncio.run(
            perform_h3_request_with_custom_authority(
                "127.0.0.1",
                port,
                authority,
                additional_headers=[("host", authority)],
                server_hostname="localhost",
                timeout=3,
            )
        )
        assert response.status_code == expected, (authority, response)


def test_connect_rejects_missing_empty_and_invalid_ports(
    tmp_path: Path, proxy_process: ProcessFactory
) -> None:
    port = get_unique_port()
    process = proxy_process(create_test_config(port, str(tmp_path)))
    assert process.wait_ready()
    for target in [
        "example.test",
        "example.test:",
        "[::1]:",
        "example.test:0",
        "example.test:abc",
        "example.test:65536",
        "user@example.test:443",
        "http://example.test:443/",
    ]:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.sendall(
                (
                    f"CONNECT {target} HTTP/1.1\r\n"
                    + "Host: example.test\r\nConnection: close\r\n\r\n"
                ).encode()
            )
            status = conn.recv(4096).split(b"\r\n", 1)[0].split()[1]
            assert status == b"400", (target, status)
