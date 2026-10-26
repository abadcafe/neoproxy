"""Wire contracts for HTTP proxy control fields across listener protocols."""

import asyncio
import socket
import ssl
from pathlib import Path
from queue import Queue
from typing import Literal

import pytest
from aioquic.asyncio.client import connect
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_protocol import EventProtocol
from tests.fixtures.http_request import send_raw_request
from tests.fixtures.ports import (
    get_unique_port,
    wait_for_proxy,
    wait_for_udp_port_bound,
)
from tests.fixtures.proxy_process import managed_processes
from tests.fixtures.tcp_peer import TargetServerFactory


async def h3_options(port: int, target: int, limit: str) -> tuple[int, list[bytes]]:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = "localhost"
    async with connect(
        "127.0.0.1", port, configuration=configuration, create_protocol=EventProtocol
    ) as protocol:
        assert isinstance(protocol, EventProtocol)
        stream = protocol.request(
            [
                (b":method", b"OPTIONS"),
                (b":scheme", b"http"),
                (b":authority", f"127.0.0.1:{target}".encode()),
                (b":path", b"/"),
                (b"max-forwards", limit.encode()),
                (b"via", b"1.0 client-gateway"),
            ],
            end_stream=True,
        )
        async with asyncio.timeout(3):
            while True:
                event = await protocol.next_event(stream)
                assert not isinstance(event, (StreamReset, ConnectionTerminated)), event
                if isinstance(event, HeadersReceived):
                    return int(dict(event.headers)[b":status"]), [
                        value for name, value in event.headers if name == b"via"
                    ]


@pytest.mark.parametrize("kind", ["http", "http3"])
def test_proxy_controls_forwarding_and_records_received_versions(
    tmp_path: Path, target_server: TargetServerFactory, kind: Literal["http", "http3"]
) -> None:
    received: Queue[bytes] = Queue()
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            conn.settimeout(3)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk
            received.put(request.lower())
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                + b"Via: 1.0 origin-gateway\r\nConnection: close\r\n\r\nOK"
            )

    _ = target_server(target, origin)
    certificate, key, _, _ = generate_test_certificates(str(tmp_path))
    port = get_unique_port()
    path = tmp_path / "proxy.yaml"
    _ = path.write_text(f"""server_threads: 1
plugins:
  http_upstream:
    upstreams: [{{name: direct}}]
listeners:
- name: main
  kind: {kind}
  addresses: ["127.0.0.1:{port}"]
services:
- name: direct
  kind: http_upstream.upstream
  args: {{upstream: direct}}
servers:
- name: main
  service: direct
  listeners: [main]
  tls:
    certificates:
    - cert_path: {certificate}
      key_path: {key}
""")
    with managed_processes() as start:
        process = start(str(path))
        ready = wait_for_proxy if kind == "http" else wait_for_udp_port_bound
        assert ready("127.0.0.1", port, timeout=3, proc=process)
        for limit, expected_status in [("0", 204), ("2", 200)]:
            if kind == "http":
                response = send_raw_request(
                    "127.0.0.1",
                    port,
                    (
                        f"OPTIONS http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                        + f"Host: 127.0.0.1:{target}\r\nMax-Forwards: {limit}\r\n"
                        + "Via: 1.0 client-gateway\r\nConnection: close\r\n\r\n"
                    ).encode(),
                )
                assert int(response.split()[1]) == expected_status
                if limit == "2":
                    assert b"via: 1.0 origin-gateway" in response.lower()
                    assert b"via: 1.1 neoproxy" in response.lower()
            else:
                status, via = asyncio.run(h3_options(port, target, limit))
                assert status == expected_status
                if limit == "2":
                    assert b"1.1 neoproxy" in via
            if limit == "0":
                assert received.empty(), "zero limit reached the origin"
            else:
                request = received.get(timeout=3)
                assert b"max-forwards: 1\r\n" in request
                assert b"via: 1.0 client-gateway\r\n" in request
                assert (
                    b"via: 1.1 neoproxy\r\n"
                    if kind == "http"
                    else b"via: 3 neoproxy\r\n"
                ) in request


def test_http_listener_routes_hostless_http10_to_default(tmp_path: Path) -> None:
    from tests.fixtures.http_configuration import create_echo_config

    port = get_unique_port()
    with managed_processes() as start:
        process = start(create_echo_config(port, str(tmp_path)))
        assert wait_for_proxy("127.0.0.1", port, timeout=3, proc=process)
        response = send_raw_request("127.0.0.1", port, b"GET / HTTP/1.0\r\n\r\n")
        assert int(response.split()[1]) == 200
