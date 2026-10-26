"""module: http3_client; responsibility: exchange requests over one H3 session.
Public operations: H3Client connect, send_request, send_connect_request,
transfer_tunnel, close; H3Response.
Data entities: H3Client, H3Response.
Tests: http3_client_tests.py and process integration contracts.
"""

import asyncio
import base64
import ipaddress
import ssl
from contextlib import AsyncExitStack
from dataclasses import dataclass

import aioquic.asyncio.client as quic_client
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnectionError
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset

from .h3_protocol import EventProtocol


@dataclass
class H3Response:
    status_code: int
    headers: dict[str, str]
    body: bytes
    stream_id: int


def _server_name(host: str, override: str | None) -> str:
    if override is not None:
        return override
    try:
        _ = ipaddress.ip_address(host)
    except ValueError:
        return host
    return "localhost"


class H3Client:
    def __init__(
        self,
        host: str,
        port: int,
        ca_path: str | None = None,
        cert_path: str | None = None,
        key_path: str | None = None,
        verify_mode: ssl.VerifyMode | None = None,
        server_hostname: str | None = None,
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.ca_path: str | None = ca_path
        self.cert_path: str | None = cert_path
        self.key_path: str | None = key_path
        self.verify_mode: ssl.VerifyMode = (
            verify_mode
            if verify_mode is not None
            else (ssl.CERT_REQUIRED if ca_path else ssl.CERT_NONE)
        )
        self.server_hostname: str = _server_name(host, server_hostname)
        self.connection_error: str = ""
        self._protocol: EventProtocol | None = None
        self._resources: AsyncExitStack = AsyncExitStack()

    async def connect(self) -> bool:
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        configuration.verify_mode = self.verify_mode
        configuration.server_name = self.server_hostname
        if self.ca_path:
            configuration.load_verify_locations(self.ca_path)
        if self.cert_path and self.key_path:
            configuration.load_cert_chain(self.cert_path, self.key_path)
        try:
            protocol = await self._resources.enter_async_context(
                quic_client.connect(
                    self.host,
                    self.port,
                    configuration=configuration,
                    create_protocol=EventProtocol,
                )
            )
        except (OSError, QuicConnectionError) as error:
            self.connection_error = str(error) or type(error).__name__
            return False
        assert isinstance(protocol, EventProtocol)
        self._protocol = protocol
        return True

    async def send_connect_request(
        self,
        target_host: str,
        target_port: int,
        username: str | None = None,
        password: str | None = None,
    ) -> H3Response:
        protocol = self._protocol
        assert protocol is not None, "connect must succeed before sending a request"
        host = (
            f"[{target_host}]"
            if ":" in target_host and not target_host.startswith("[")
            else target_host
        )
        headers = [
            (b":method", b"CONNECT"),
            (b":authority", f"{host}:{target_port}".encode()),
        ]
        if username is not None and password is not None:
            credentials = base64.b64encode(f"{username}:{password}".encode())
            headers.append((b"proxy-authorization", b"Basic " + credentials))
        stream = protocol.request(headers, end_stream=False)
        return await self._receive_response(stream, headers_only=True)

    async def send_request(
        self,
        method: str,
        path: str,
        headers: list[tuple[str, str]] | None = None,
        body: bytes | None = None,
        *,
        authority: str | None = None,
    ) -> H3Response:
        protocol = self._protocol
        assert protocol is not None, "connect must succeed before sending a request"
        fields = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (
                b":authority",
                (
                    authority
                    if authority is not None
                    else f"{self.server_hostname}:{self.port}"
                ).encode(),
            ),
            (b":path", path.encode()),
        ]
        fields.extend((name.encode(), value.encode()) for name, value in headers or [])
        stream = protocol.request(fields, end_stream=not body)
        if body:
            protocol.send_data(stream, body, end_stream=True)
        return await self._receive_response(stream, headers_only=False)

    async def _receive_response(self, stream: int, *, headers_only: bool) -> H3Response:
        protocol = self._protocol
        assert protocol is not None
        status = 0
        headers: dict[str, str] = {}
        body = bytearray()
        try:
            async with asyncio.timeout(10):
                while True:
                    event = await protocol.next_event(stream)
                    if isinstance(event, (StreamReset, ConnectionTerminated)):
                        return H3Response(0, {}, str(event).encode(), stream)
                    if isinstance(event, HeadersReceived):
                        fields = dict(event.headers)
                        if b":status" in fields:
                            status = int(fields[b":status"])
                            if status < 200:
                                continue
                        for name, value in event.headers:
                            if not name.startswith(b":"):
                                headers[name.decode()] = value.decode()
                        if headers_only and status:
                            break
                    elif isinstance(event, DataReceived):
                        body.extend(event.data)
                    if (
                        isinstance(event, (HeadersReceived, DataReceived))
                        and event.stream_ended
                    ):
                        break
                    if isinstance(event, StreamDataReceived) and event.end_stream:
                        break
        except TimeoutError:
            return H3Response(0, {}, b"Timeout", stream)
        return H3Response(status, headers, bytes(body), stream)

    async def transfer_tunnel(self, stream: int, data: bytes) -> bytes | None:
        protocol = self._protocol
        assert protocol is not None
        protocol.send_data(stream, data, end_stream=True)
        received = bytearray()
        try:
            async with asyncio.timeout(10):
                while True:
                    event = await protocol.next_event(stream)
                    if isinstance(event, (StreamReset, ConnectionTerminated)):
                        return None
                    if isinstance(event, DataReceived):
                        received.extend(event.data)
                    if (
                        isinstance(event, (HeadersReceived, DataReceived))
                        and event.stream_ended
                    ):
                        break
                    if isinstance(event, StreamDataReceived) and event.end_stream:
                        break
        except TimeoutError:
            return None
        return bytes(received)

    async def close(self) -> None:
        await self._resources.aclose()
        self._protocol = None
