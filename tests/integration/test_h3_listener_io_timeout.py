"""HTTP/3 request inactivity is isolated to its stream and tracks raw bytes."""

import asyncio
import socket
from pathlib import Path

import pytest
from aioquic.asyncio.client import connect
from aioquic.h3.connection import FrameType, encode_frame
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset
from pylsqpack import Encoder

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_protocol import EventProtocol
from tests.fixtures.http_policy_scenario import configuration, read_request
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import TargetServerFactory


@pytest.mark.asyncio
@pytest.mark.parametrize("progress", [False, True])
async def test_h3_body_timeout_and_fragmented_trailer_progress(
    tmp_path: Path, target_server: TargetServerFactory, progress: bool
) -> None:
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            data = read_request(conn).split(b"\r\n\r\n", 1)[1]
            while not data.endswith(b"\r\n\r\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    _ = target_server(target, origin)
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    config = configuration({"kind": "http3", "body_read_timeout": "300ms"}, {})
    config["servers"] = [
        {
            "name": "main",
            "listeners": ["main"],
            "service": "main",
            "certificates": [{"cert_path": cert, "key_path": key}],
        }
    ]
    quic = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    quic.server_name = "localhost"
    quic.load_verify_locations(ca)
    with running_proxy(tmp_path, config) as proxy:
        async with connect(
            "127.0.0.1", proxy.port, configuration=quic, create_protocol=EventProtocol
        ) as protocol:
            assert isinstance(protocol, EventProtocol)
            stream = protocol.request(
                [
                    (b":method", b"POST"),
                    (b":scheme", b"http"),
                    (b":authority", f"127.0.0.1:{target}".encode()),
                    (b":path", b"/"),
                    (b"trailer", b"x-test"),
                ],
                end_stream=False,
            )
            if progress:
                protocol.send_data(stream, b"a", end_stream=False)
                encoder = Encoder()
                _, block = encoder.encode(stream, [(b"x-test", b"aaaaaaaaaaaa")])
                wire = encode_frame(FrameType.HEADERS, block)
                for offset in range(len(wire)):
                    protocol.quic_connection.send_stream_data(
                        stream,
                        wire[offset : offset + 1],
                        end_stream=offset == len(wire) - 1,
                    )
                    protocol.transmit()
                    await asyncio.sleep(0.08)
            async with asyncio.timeout(3):
                while True:
                    event = await protocol.next_event(stream)
                    assert not isinstance(event, (StreamReset, ConnectionTerminated)), (
                        event
                    )
                    if isinstance(event, HeadersReceived):
                        assert dict(event.headers)[b":status"] == (
                            b"200" if progress else b"408"
                        )
                        break
