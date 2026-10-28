"""Count actual upstream QUIC connections during concurrent proxy requests."""

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, override

import pytest
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted, QuicEvent

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer

type RequestKind = Literal["forward", "tunnel", "mixed"]

COLD_REQUESTS = 16
WARM_REQUESTS = 4


@dataclass
class Observations:
    connections: int = 0
    handshakes: int = 0
    requests: list[tuple[int, int, bytes]] = field(default_factory=list)
    all_cold_requests: asyncio.Event = field(default_factory=asyncio.Event)


class CountingPeer(QuicConnectionProtocol):
    def __init__(
        self,
        quic: QuicConnection,
        observations: Observations,
        stream_handler: QuicStreamHandler | None = None,
    ) -> None:
        super().__init__(quic, stream_handler)
        self.observations: Observations = observations
        self.connection_number: int = observations.connections
        observations.connections += 1
        self.http: H3Connection = H3Connection(quic)
        self.methods: dict[int, bytes] = {}
        self.responses_released: bool = False

    @override
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self.observations.handshakes += 1
        for message in self.http.handle_event(event):
            if isinstance(message, HeadersReceived):
                headers = dict(message.headers)
                method = headers[b":method"]
                self.methods[message.stream_id] = method
                self.observations.requests.append(
                    (self.connection_number, message.stream_id, method)
                )
                if len(self.observations.requests) == COLD_REQUESTS:
                    self.observations.all_cold_requests.set()
                if self.responses_released:
                    self.respond(message.stream_id, method)
            elif isinstance(message, DataReceived):
                if self.methods[message.stream_id] == b"CONNECT":
                    self.http.send_data(
                        message.stream_id,
                        message.data,
                        end_stream=message.stream_ended,
                    )
                    self.transmit()

    def respond(self, stream_id: int, method: bytes) -> None:
        if method == b"CONNECT":
            # This peer exercises connection sharing, not strict
            # classic CONNECT field validation. The h3 dependency's
            # extra :scheme/:path fields have a separate failure case.
            self.http.send_headers(stream_id, [(b":status", b"200")])
        else:
            self.http.send_headers(
                stream_id, [(b":status", b"200"), (b"content-length", b"2")]
            )
            self.http.send_data(stream_id, b"OK", end_stream=True)
        self.transmit()

    def release_responses(self) -> None:
        self.responses_released = True
        for stream_id, method in self.methods.items():
            self.respond(stream_id, method)


def _method(kind: RequestKind, index: int) -> bytes:
    if kind == "tunnel" or (kind == "mixed" and index % 2):
        return b"CONNECT"
    return b"GET"


async def _exercise_connection_sharing(
    directory: Path, kind: RequestKind, maximum: int
) -> None:
    certificate, key, ca, _ = generate_test_certificates(str(directory))
    observations = Observations()
    peers: list[CountingPeer] = []

    def create_peer(
        quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
    ) -> CountingPeer:
        peer = CountingPeer(quic, observations, stream_handler)
        peers.append(peer)
        return peer

    upstream = get_unique_port()
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(certificate, key)
    server = await serve(
        "127.0.0.1",
        upstream,
        configuration=configuration,
        create_protocol=create_peer,
    )
    entry = get_unique_port()
    config = directory / "entry.yaml"
    _ = config.write_text(f"""server_threads: 4
plugins:
  upstream:
    connection_pools:
      - name: default
        http3_pool_max_connections_per_host: {maximum}
        certificates:
          server_ca_path: {ca}
    upstream_request_timeout: 10s
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
        connected = asyncio.Event()
        start = asyncio.Event()
        connected_count = 0

        async def request(index: int) -> None:
            nonlocal connected_count
            reader, writer = await asyncio.open_connection("127.0.0.1", entry)
            try:
                connected_count += 1
                if connected_count == COLD_REQUESTS:
                    connected.set()
                _ = await start.wait()
                method = _method(kind, index)
                if method == b"CONNECT":
                    target = f"target-{index}.test:443"
                else:
                    target = f"http://target.test/item-{index}"
                writer.write(
                    method
                    + f" {target} HTTP/1.1\r\nHost: target.test\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                )
                await writer.drain()
                headers = await reader.readuntil(b"\r\n\r\n")
                assert b" 200 " in headers.split(b"\r\n", 1)[0], headers
                if method == b"CONNECT":
                    for turn in range(2):
                        payload = f"tunnel-{index}-turn-{turn}".encode() + b"\x00\xff"
                        writer.write(payload)
                        await writer.drain()
                        assert await reader.readexactly(len(payload)) == payload
                else:
                    assert await reader.readexactly(2) == b"OK"
            finally:
                await close_writer(writer)

        async with asyncio.timeout(8):
            async with asyncio.TaskGroup() as tasks:
                for index in range(COLD_REQUESTS):
                    _ = tasks.create_task(request(index))
                _ = await connected.wait()
                assert observations.connections == 0
                start.set()
                # No responses are sent until every request has opened
                # its H3 stream. Holding a connection-state lock during
                # request/response handling would stall at this barrier.
                _ = await observations.all_cold_requests.wait()
                assert observations.connections == maximum, observations
                assert observations.handshakes == maximum, observations
                assert (
                    len({(conn, stream) for conn, stream, _ in observations.requests})
                    == COLD_REQUESTS
                )
                for peer in peers:
                    peer.release_responses()

            assert len(observations.requests) == COLD_REQUESTS
            async with asyncio.TaskGroup() as tasks:
                for index in range(COLD_REQUESTS, COLD_REQUESTS + WARM_REQUESTS):
                    _ = tasks.create_task(request(index))

        assert observations.connections == maximum, observations
        assert observations.handshakes == maximum, observations
        assert len(observations.requests) == COLD_REQUESTS + WARM_REQUESTS
        expected_methods = [
            _method(kind, index) for index in range(COLD_REQUESTS + WARM_REQUESTS)
        ]
        for method in (b"GET", b"CONNECT"):
            assert sum(
                value == method for _, _, value in observations.requests
            ) == expected_methods.count(method)
    finally:
        terminate_process(process, force=True)
        server.close()


@pytest.mark.parametrize("maximum", [1, 2])
@pytest.mark.parametrize("kind", ["forward", "tunnel", "mixed"])
def test_concurrent_requests_share_bounded_upstream_quic_connections(
    tmp_path: Path, kind: RequestKind, maximum: int
) -> None:
    asyncio.run(_exercise_connection_sharing(tmp_path, kind, maximum))
