"""Process regressions for protocol boundaries found during the project review."""

import asyncio
import socket
import ssl
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal

import pytest
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_lifecycle import LifecycleClient
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.tcp_peer import TargetServerFactory


@contextmanager
def running_proxy(directory: Path, content: str) -> Generator[ProxyProcess]:
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / "server.yaml"
    _ = config.write_text(content)
    process = start_proxy(str(config))
    try:
        yield process
    finally:
        terminate_process(process, timeout=5, force=True)


def echo_config(port: int, listener: str, tls: str = "") -> str:
    return f"""server_threads: 1
plugins:
  echo: {{}}
listeners:
- name: main
  kind: {listener}
  addresses: ["127.0.0.1:{port}"]
services:
- name: echo
  kind: echo.echo
servers:
- name: echo
  listeners: [main]
  service: echo
{tls}
"""


def test_https_accepts_clients_while_another_handshake_stalls(tmp_path: Path) -> None:
    cert, key, _, _ = generate_test_certificates(str(tmp_path))
    port = get_unique_port()
    tls = f"  tls:\n    certificates:\n    - cert_path: {cert}\n      key_path: {key}"
    with running_proxy(tmp_path, echo_config(port, "https", tls)) as process:
        assert process.wait_ready(timeout=3)
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as conn:
                    conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    assert b"200" in conn.recv(4096)


async def stream_echo(port: int) -> None:
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = ssl.CERT_NONE
    config.server_name = "localhost"
    async with connect(
        "127.0.0.1", port, configuration=config, create_protocol=LifecycleClient
    ) as protocol:
        assert isinstance(protocol, LifecycleClient)
        stream = protocol.request(b"POST", b"localhost")
        protocol.http.send_data(stream, b"first", end_stream=False)
        protocol.transmit()
        # A response must arrive before the upload reaches EOF.
        async with asyncio.timeout(2):
            await protocol.read_data(stream, b"first")
        trailers = [(b"x-checksum", b"complete")]
        protocol.http.send_headers(stream, trailers, end_stream=True)
        protocol.transmit()
        async with asyncio.timeout(2):
            # FIN may follow trailers in a separate packet, including
            # a reserved GREASE frame. Require both the trailers and
            # actual stream completion, without assuming packet grouping.
            assert await protocol.read_end(stream) == trailers


def test_http3_streams_echo_before_upload_eof_and_preserves_trailers(
    tmp_path: Path,
) -> None:
    cert, key, _, _ = generate_test_certificates(str(tmp_path))
    port = get_unique_port()
    tls = f"  tls:\n    certificates:\n    - cert_path: {cert}\n      key_path: {key}"
    with running_proxy(
        tmp_path,
        echo_config(port, "http3", tls).replace(
            "server_threads: 1", "server_threads: 2"
        ),
    ) as process:
        assert process.wait_ready(timeout=3)
        asyncio.run(stream_echo(port))


def test_http3_chain_streams_response_before_upload_eof(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    upstream = get_unique_port()
    entry = get_unique_port()
    tls = f"  tls:\n    certificates:\n    - cert_path: {cert}\n      key_path: {key}"
    chain = f"""server_threads: 1
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
"""
    with running_proxy(
        tmp_path / "upstream", echo_config(upstream, "http3", tls)
    ) as remote:
        assert remote.wait_ready(timeout=3)
        with running_proxy(tmp_path / "entry", chain) as local:
            assert local.wait_ready(timeout=3)
            with socket.create_connection(("127.0.0.1", entry), timeout=3) as conn:
                conn.sendall(
                    (
                        b"POST http://localhost/upload HTTP/1.1\r\nHost: localhost\r\n"
                        + b"Transfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n"
                    )
                )
                response = b""
                while b"first" not in response:
                    chunk = conn.recv(4096)
                    assert chunk
                    response += chunk
                assert b"200" in response.split(b"\r\n", 1)[0]


def test_http_chain_connect_response_has_a_deadline(
    tmp_path: Path, target_server: TargetServerFactory
) -> None:
    import threading

    release = threading.Event()
    upstream = get_unique_port()
    entry = get_unique_port()

    def silent_proxy(conn: socket.socket) -> None:
        try:
            _ = conn.recv(4096)
            _ = release.wait(3)
        finally:
            conn.close()

    _ = target_server(upstream, silent_proxy)
    config = f"""server_threads: 1
plugins:
  http_upstream:
    request_timeout: 100ms
    upstreams:
    - name: relay
      addresses:
      - address: 127.0.0.1:{upstream}
        http: {{}}
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
"""
    try:
        with running_proxy(tmp_path, config) as process:
            assert process.wait_ready(timeout=3)
            with socket.create_connection(("127.0.0.1", entry), timeout=2) as conn:
                conn.sendall(
                    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
                )
                assert b"504" in conn.recv(4096).split(b"\r\n", 1)[0]
    finally:
        release.set()


@pytest.mark.parametrize("listener_kind", ["http", "https"])
@pytest.mark.parametrize(
    "header_timeout", [pytest.param(None, marks=pytest.mark.slow), "100ms"]
)
def test_http_incomplete_headers_expire(
    tmp_path: Path,
    listener_kind: Literal["http", "https"],
    header_timeout: str | None,
) -> None:
    port = get_unique_port()
    tls = ""
    if listener_kind == "https":
        cert, key, _, _ = generate_test_certificates(str(tmp_path))
        tls = (
            f"  tls:\n    certificates:\n    - cert_path: {cert}\n      key_path: {key}"
        )
    config = echo_config(port, listener_kind, tls)
    if header_timeout is not None:
        config = config.replace(
            f"  kind: {listener_kind}\n",
            f"  kind: {listener_kind}\n  args:\n"
            + f"    header_read_timeout: {header_timeout}\n",
        )
    with running_proxy(tmp_path, config) as process:
        assert process.wait_ready(timeout=3)
        with ExitStack() as connections:
            conn: socket.socket = connections.enter_context(
                socket.create_connection(("127.0.0.1", port), timeout=2)
            )
            if listener_kind == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = connections.enter_context(
                    context.wrap_socket(conn, server_hostname="localhost")
                )
            # The default follows Hyper's 30s; explicit configuration can
            # override it. Leave scheduling margin for the server deadline.
            conn.settimeout(35 if header_timeout is None else 2)
            conn.sendall(b"GET / HTTP/1.1\r\nHost:")
            response = conn.recv(4096)
            assert not response or b"408" in response.split(b"\r\n", 1)[0]
