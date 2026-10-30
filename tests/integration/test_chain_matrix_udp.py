"""RFC 9298 direct and mixed-protocol UDP tunnel contracts."""

import asyncio
import socket
import ssl
from contextlib import ExitStack
from pathlib import Path
from typing import Literal, final, override

import pytest
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicStreamHandler
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DatagramReceived, DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, QuicEvent
from pydantic import TypeAdapter

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict, JsonValue
from tests.fixtures.h3_protocol import H3ProtocolBase
from tests.fixtures.http_scenario import running_proxy

type Protocol = Literal["http", "https", "http3"]


def capsule(data: bytes) -> bytes:
    length = len(data) + 1
    assert length < 16384
    encoded = bytes([length]) if length < 64 else (length | 0x4000).to_bytes(2)
    return b"\x00" + encoded + b"\x00" + data


@final
class UdpClient(H3ProtocolBase):
    def __init__(
        self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
    ) -> None:
        super().__init__(quic, stream_handler)
        self.h3_connection = H3Connection(quic, enable_webtransport=True)
        self.events: asyncio.Queue[
            HeadersReceived | DataReceived | DatagramReceived
        ] = asyncio.Queue()
        self.terminated: asyncio.Future[ConnectionTerminated] = (
            asyncio.get_running_loop().create_future()
        )

    @override
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated) and not self.terminated.done():
            self.terminated.set_result(event)
        http = self.h3_connection
        assert http is not None
        for message in http.handle_event(event):
            if isinstance(message, (HeadersReceived, DataReceived, DatagramReceived)):
                self.events.put_nowait(message)


async def echo_udp(server: socket.socket) -> None:
    loop = asyncio.get_running_loop()
    while True:
        result = TypeAdapter(tuple[bytes, tuple[str, int]]).validate_python(
            await loop.sock_recvfrom(server, 65536)
        )
        data, address = result
        _ = await loop.sock_sendto(server, data, address)


def configuration(
    protocol: Protocol,
    cert: str,
    key: str,
    ca: str,
    next_hop: tuple[Protocol, int] | None,
    listener_datagrams: bool = True,
    pool_datagrams: bool = True,
) -> ConfigDict:
    upstream: dict[str, JsonValue] = {"name": "route"}
    if next_hop is not None:
        kind, port = next_hop
        upstream["addresses"] = [
            {
                "address": f"127.0.0.1:{port}",
                "hostname": "localhost",
                "address_protocol": kind,
                "user": {"username": "user", "password": "password"},
            }
        ]
    server: dict[str, JsonValue] = {
        "name": "entry",
        "listeners": ["entry"],
        "service": "route",
    }
    if protocol != "http":
        server["certificates"] = [{"cert_path": cert, "key_path": key}]
    listener: dict[str, JsonValue] = {"name": "entry", "kind": protocol}
    if protocol == "http3":
        listener.update(
            {
                "http3_enable_datagram": listener_datagrams,
                "quic_connection_datagram_receive_buffer_size": "2MiB",
                "quic_connection_datagram_send_buffer_size": "3MiB",
            }
        )
    return {
        "plugins": {
            "auth": {},
            "upstream": {
                "connection_pools": [
                    {
                        "name": "default",
                        "certificates": {"server_ca_path": ca},
                        "http3_enable_datagram": pool_datagrams,
                        "quic_connection_datagram_receive_buffer_size": "2MiB",
                        "quic_connection_datagram_send_buffer_size": "3MiB",
                    }
                ],
                "upstreams": [upstream],
            },
        },
        "listeners": [listener],
        "services": [
            {
                "name": "route",
                "kind": "upstream.upstream",
                "upstream": "route",
                "layers": [
                    {
                        "kind": "auth.basic_auth",
                        "users": [{"username": "user", "password": "password"}],
                    }
                ],
            }
        ],
        "servers": [server],
    }


def http_exchange(port: int, target: int, protocol: Protocol, ca: str) -> None:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    stream = (
        ssl.create_default_context(cafile=ca).wrap_socket(
            raw, server_hostname="localhost"
        )
        if protocol == "https"
        else raw
    )
    with stream:
        path = f"/.well-known/masque/udp/127.0.0.1/{target}/"
        stream.sendall(
            (
                f"GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n"
                "Connection: Upgrade\r\nUpgrade: connect-udp\r\n"
                "Capsule-Protocol: ?1\r\n"
                "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n"
            ).encode()
        )
        with stream.makefile("rb") as reader:
            assert reader.readline().split()[1] == b"101"
            while reader.readline() != b"\r\n":
                pass
            for data in [b"", b"hello", bytes(range(256)) * 4]:
                encoded = capsule(data)
                stream.sendall(encoded)
                assert reader.read(len(encoded)) == encoded


async def h3_exchange(
    port: int, target: int, ca: str, datagram: bool, expect_datagram: bool = True
) -> None:
    config = QuicConfiguration(
        is_client=True, alpn_protocols=["h3"], max_datagram_frame_size=65536
    )
    config.server_name = "localhost"
    config.load_verify_locations(cafile=ca)
    async with connect(
        "127.0.0.1", port, configuration=config, create_protocol=UdpClient
    ) as client:
        assert isinstance(client, UdpClient)
        http = client.h3_connection
        assert http is not None
        stream = client.quic_connection.get_next_available_stream_id()
        http.send_headers(
            stream,
            [
                (b":method", b"CONNECT"),
                (b":protocol", b"connect-udp"),
                (b":scheme", b"https"),
                (b":authority", f"localhost:{port}".encode()),
                (b":path", f"/.well-known/masque/udp/127.0.0.1/{target}/".encode()),
                (b"capsule-protocol", b"?1"),
                (b"proxy-authorization", b"Basic dXNlcjpwYXNzd29yZA=="),
            ],
        )
        client.transmit()
        headers = await asyncio.wait_for(client.events.get(), 5)
        assert isinstance(headers, HeadersReceived)
        assert (b":status", b"200") in headers.headers
        for data in [b"", b"hello", b"x" * 800]:
            if datagram:
                http.send_datagram(stream, b"\x00" + data)
            else:
                http.send_data(stream, capsule(data), end_stream=False)
            client.transmit()
            response = await asyncio.wait_for(client.events.get(), 5)
            if datagram:
                assert isinstance(response, DatagramReceived)
            if not expect_datagram:
                assert isinstance(response, DataReceived)
            if isinstance(response, DatagramReceived):
                assert response.data == b"\x00" + data
            else:
                assert isinstance(response, DataReceived)
                received = response.data
                while len(received) < len(capsule(data)):
                    response = await asyncio.wait_for(client.events.get(), 5)
                    assert isinstance(response, DataReceived)
                    received += response.data
                assert received == capsule(data)
        http.send_data(stream, b"", end_stream=True)
        client.transmit()


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", ["http", "https", "http3"])
@pytest.mark.parametrize("hop", [None, "http", "https", "http3"])
@pytest.mark.parametrize(
    "listener_datagrams,pool_datagrams",
    [(True, True), (False, True), (True, False), (False, False)],
)
async def test_connect_udp_direct_and_mixed_chain(
    tmp_path: Path,
    entry: Protocol,
    hop: Protocol | None,
    listener_datagrams: bool,
    pool_datagrams: bool,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, ExitStack() as stack:
        udp.bind(("127.0.0.1", 0))
        target = TypeAdapter(tuple[str, int]).validate_python(udp.getsockname())[1]
        assert isinstance(target, int)
        udp.setblocking(False)
        task = asyncio.create_task(echo_udp(udp))
        try:
            next_hop: tuple[Protocol, int] | None = None
            if hop is not None:
                exit_proxy = stack.enter_context(
                    running_proxy(
                        tmp_path / "exit",
                        configuration(
                            hop, cert, key, ca, None, listener_datagrams=pool_datagrams
                        ),
                    )
                )
                next_hop = (hop, exit_proxy.port)
            proxy = stack.enter_context(
                running_proxy(
                    tmp_path / "entry",
                    configuration(
                        entry,
                        cert,
                        key,
                        ca,
                        next_hop,
                        listener_datagrams=listener_datagrams,
                        pool_datagrams=pool_datagrams,
                    ),
                )
            )
            if entry == "http3":
                await h3_exchange(
                    proxy.port, target, ca, False, expect_datagram=listener_datagrams
                )
                if listener_datagrams:
                    await h3_exchange(proxy.port, target, ca, True)
            else:
                await asyncio.to_thread(http_exchange, proxy.port, target, entry, ca)
        finally:
            _ = task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


@pytest.mark.parametrize("protocol", ["http", "https"])
@pytest.mark.parametrize("authorized", [False, True])
def test_connect_udp_requires_authentication_and_valid_target(
    tmp_path: Path, protocol: Protocol, authorized: bool
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    with running_proxy(tmp_path, configuration(protocol, cert, key, ca, None)) as proxy:
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        stream = (
            ssl.create_default_context(cafile=ca).wrap_socket(
                raw, server_hostname="localhost"
            )
            if protocol == "https"
            else raw
        )
        auth = (
            "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n" if authorized else ""
        )
        with stream:
            stream.sendall(
                (
                    "GET /.well-known/masque/udp/localhost/0/ HTTP/1.1\r\n"
                    "Host: localhost\r\nConnection: Upgrade\r\n"
                    "Upgrade: connect-udp\r\n"
                    f"Capsule-Protocol: ?1\r\n{auth}\r\n"
                ).encode()
            )
            with stream.makefile("rb") as reader:
                assert reader.readline().split()[1] == (
                    b"400" if authorized else b"407"
                )


@pytest.mark.asyncio
@pytest.mark.parametrize("quarter", [1 << 60, (1 << 62) - 1])
async def test_connect_udp_rejects_datagram_stream_id_outside_quic_range(
    tmp_path: Path,
    quarter: int,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    config = QuicConfiguration(
        is_client=True, alpn_protocols=["h3"], max_datagram_frame_size=65536
    )
    config.server_name = "localhost"
    config.load_verify_locations(cafile=ca)
    with running_proxy(tmp_path, configuration("http3", cert, key, ca, None)) as proxy:
        async with connect(
            "127.0.0.1", proxy.port, configuration=config, create_protocol=UdpClient
        ) as client:
            assert isinstance(client, UdpClient)
            client.quic_connection.send_datagram_frame(
                (quarter | (3 << 62)).to_bytes(8, "big") + b"\x00packet"
            )
            client.transmit()
            terminated = await asyncio.wait_for(client.terminated, 3)
            assert terminated.error_code == 0x33
