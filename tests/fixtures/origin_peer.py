"""module: origin_peer; responsibility: serve observable origin protocol exchanges.
Public operations: PeerConfig, SeenRequest, OriginPeer, origin_peer.
Data entities: those types. Tests: test_origin_discovery.py.
"""

import asyncio
import ssl
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Literal, override

import h2.config
import h2.connection
import h2.events
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamDataReceived
from pydantic import BaseModel

from .ports import get_unique_port
from .stream_cleanup import close_writer


class PeerConfig(BaseModel):
    certificate: str
    key: str
    wire: Literal["h1", "h2", "h3"]


@dataclass(frozen=True)
class SeenRequest:
    headers: dict[str, str]
    body: bytes
    connection: int


@dataclass
class OriginPeer:
    port: int
    headers: dict[str, str] = field(default_factory=dict)
    requests: list[SeenRequest] = field(default_factory=list)
    status: int = 200
    abort_response: bool = False
    closed_connections: int = 0
    response_delay: float = 0


@asynccontextmanager
async def origin_peer(config: PeerConfig) -> AsyncGenerator[OriginPeer]:
    peer = OriginPeer(get_unique_port())

    def response_fields(body: bytes) -> list[tuple[bytes, bytes]]:
        return [
            (b":status", str(peer.status).encode()),
            (b"content-length", str(len(body)).encode()),
            *((name.encode(), value.encode()) for name, value in peer.headers.items()),
        ]

    class OriginProtocol(QuicConnectionProtocol):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.connection: QuicConnection = quic
            self.http: H3Connection = H3Connection(quic)
            self.headers: dict[int, dict[str, str]] = {}
            self.bodies: dict[int, bytearray] = {}

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            if isinstance(event, ConnectionTerminated):
                peer.closed_connections += 1
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    self.headers[message.stream_id] = {
                        name.decode(): value.decode() for name, value in message.headers
                    }
                    self.bodies[message.stream_id] = bytearray()
                elif isinstance(message, DataReceived):
                    self.bodies[message.stream_id].extend(message.data)
                if (
                    isinstance(message, (HeadersReceived, DataReceived))
                    and message.stream_ended
                ):
                    self.respond(message.stream_id)
            # aioquic can omit a terminal H3 event when GREASE precedes FIN.
            if (
                isinstance(event, StreamDataReceived)
                and event.end_stream
                and event.stream_id in self.headers
            ):
                self.respond(event.stream_id)

        def respond(self, stream: int) -> None:
            body = bytes(self.bodies.pop(stream))
            peer.requests.append(SeenRequest(self.headers.pop(stream), body, id(self)))
            if peer.abort_response:
                self.connection.reset_stream(stream, 0x102)
                self.transmit()
                return
            payload = body or b"h3"
            self.http.send_headers(stream, response_fields(payload))
            if peer.response_delay:

                def finish() -> None:
                    self.http.send_data(stream, payload, end_stream=True)
                    self.transmit()

                _ = asyncio.get_running_loop().call_later(peer.response_delay, finish)
            else:
                self.http.send_data(stream, payload, end_stream=True)
            self.transmit()

    if config.wire == "h3":
        quic = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        quic.load_cert_chain(config.certificate, config.key)
        server = await serve(
            "127.0.0.1", peer.port, configuration=quic, create_protocol=OriginProtocol
        )
        try:
            yield peer
        finally:
            server.close()
        return

    async def http_peer(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            if config.wire == "h1":
                while True:
                    try:
                        header = await reader.readuntil(b"\r\n\r\n")
                    except asyncio.IncompleteReadError:
                        break
                    lines = header.split(b"\r\n")
                    fields = {
                        name.decode().lower(): value.strip().decode()
                        for line in lines[1:]
                        if (name_and_value := line.partition(b":"))[1]
                        for name, _, value in [name_and_value]
                    }
                    body = await reader.readexactly(
                        int(fields.get("content-length", "0"))
                    )
                    peer.requests.append(SeenRequest(fields, body, id(writer)))
                    payload = body or b"h1"
                    writer.write(
                        f"HTTP/1.1 {peer.status} OK\r\n".encode()
                        + b"".join(
                            name + b": " + value + b"\r\n"
                            for name, value in response_fields(payload)[1:]
                        )
                        + b"\r\n"
                        + payload
                    )
                    await writer.drain()
            else:
                connection = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(
                        client_side=False, header_encoding="utf-8"
                    )
                )
                connection.initiate_connection()
                writer.write(connection.data_to_send())
                headers: dict[int, dict[str, str]] = {}
                bodies: dict[int, bytearray] = {}
                while data := await reader.read(65536):
                    for event in connection.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            headers[event.stream_id] = {
                                str(name): str(value) for name, value in event.headers
                            }
                            bodies[event.stream_id] = bytearray()
                        elif isinstance(event, h2.events.DataReceived):
                            bodies[event.stream_id].extend(event.data)
                            connection.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id
                            )
                        elif isinstance(event, h2.events.StreamEnded):
                            body = bytes(bodies.pop(event.stream_id))
                            peer.requests.append(
                                SeenRequest(
                                    headers.pop(event.stream_id), body, id(writer)
                                )
                            )
                            payload = body or b"h2"
                            connection.send_headers(
                                event.stream_id, response_fields(payload)
                            )
                            connection.send_data(
                                event.stream_id, payload, end_stream=True
                            )
                    writer.write(connection.data_to_send())
                    await writer.drain()
        except ConnectionResetError, BrokenPipeError:
            pass
        finally:
            await close_writer(writer)

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(config.certificate, config.key)
    tls.set_alpn_protocols(["h2"] if config.wire == "h2" else ["http/1.1"])
    server = await asyncio.start_server(http_peer, "127.0.0.1", peer.port, ssl=tls)
    async with server:
        yield peer
