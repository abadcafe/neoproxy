"""Public wire behavior of the HTTP/3 custom-authority client."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import override

import aioquic.asyncio.client as quic_client
import pytest
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent

from tests.fixtures import http3_client
from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.http3_client import H3Response
from tests.fixtures.ports import get_unique_port

RESPONSE_BODY = b"received request\x00\xff"


@dataclass(frozen=True)
class CapturePeer:
    port: int
    ca_path: str
    received: asyncio.Queue[HeadersReceived]


@asynccontextmanager
async def capture_peer(directory: Path) -> AsyncGenerator[CapturePeer, None]:
    certificate, key, ca, _ = generate_test_certificates(str(directory))
    received: asyncio.Queue[HeadersReceived] = asyncio.Queue()

    class CaptureProtocol(QuicConnectionProtocol):
        def __init__(
            self, quic: QuicConnection, stream_handler: QuicStreamHandler | None = None
        ) -> None:
            super().__init__(quic, stream_handler)
            self.http: H3Connection = H3Connection(quic)

        @override
        def quic_event_received(self, event: QuicEvent) -> None:
            for message in self.http.handle_event(event):
                if isinstance(message, HeadersReceived):
                    received.put_nowait(message)
                    self.http.send_headers(
                        message.stream_id,
                        [
                            (b":status", b"201"),
                            (b"x-peer", b"capture-peer"),
                            (b"content-length", str(len(RESPONSE_BODY)).encode()),
                        ],
                    )
                    self.http.send_data(
                        message.stream_id, RESPONSE_BODY, end_stream=True
                    )
                    self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    configuration.load_cert_chain(certificate, key)
    port = get_unique_port()
    server = await serve(
        "127.0.0.1", port, configuration=configuration, create_protocol=CaptureProtocol
    )
    try:
        yield CapturePeer(port, ca, received)
    finally:
        server.close()


def assert_response(response: H3Response, request: HeadersReceived) -> None:
    assert response.status_code == 201
    assert response.headers["x-peer"] == "capture-peer"
    assert response.body == RESPONSE_BODY
    assert response.stream_id == request.stream_id


@asynccontextmanager
async def failing_h3_connect(*_args: object, **_kwargs: object) -> AsyncGenerator[None]:
    # Simulate the normal network failure raised by the aioquic dependency.
    def fail() -> None:
        raise OSError("connection refused")

    fail()
    yield


class TestH3CustomAuthority:
    """Tests for HTTP/3 custom authority functionality."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "authority", ["service.example:8443", "other.example", "[2001:db8::1]:443"]
    )
    async def test_custom_authority_sent_correctly(
        self, tmp_path: Path, authority: str
    ) -> None:
        """Verify decoded wire headers, independent of connection address and SNI."""
        async with capture_peer(tmp_path) as peer:
            response = await http3_client.perform_h3_request_with_custom_authority(
                host="127.0.0.1",
                port=peer.port,
                custom_authority=authority,
                path="/route?query=authority",
                method="POST",
                ca_path=peer.ca_path,
                server_hostname="localhost",
                timeout=2,
            )
            request = await asyncio.wait_for(peer.received.get(), timeout=1)
            assert_response(response, request)
            fields = dict(request.headers)
            assert fields[b":authority"] == authority.encode()
            assert [name for name, _ in request.headers].count(b":authority") == 1
            assert fields[b":method"] == b"POST"
            assert fields[b":scheme"] == b"https"
            assert fields[b":path"] == b"/route?query=authority"

    @pytest.mark.asyncio
    async def test_custom_authority_connection_failure_returns_error_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Should return H3Response even when connection fails."""
        monkeypatch.setattr(quic_client, "connect", failing_h3_connect)

        response = await http3_client.perform_h3_request_with_custom_authority(
            host="127.0.0.1",
            port=1,
            custom_authority="test.example.com:443",
            timeout=1.0,
        )
        assert isinstance(response, H3Response)
        assert response.status_code == 0
        assert b"connection refused" in response.body.lower()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "additional_headers",
        [
            [
                ("host", "service.example:8443"),
                ("x-custom-header", "test-value"),
                ("x-empty", ""),
            ],
            [("x-repeat", "first"), ("x-repeat", "second")],
        ],
    )
    async def test_custom_authority_with_additional_headers(
        self, tmp_path: Path, additional_headers: list[tuple[str, str]]
    ) -> None:
        """Verify values and duplicate order observed by a real H3 peer."""
        original = list(additional_headers)
        async with capture_peer(tmp_path) as peer:
            response = await http3_client.perform_h3_request_with_custom_authority(
                host="127.0.0.1",
                port=peer.port,
                custom_authority="service.example:8443",
                additional_headers=additional_headers,
                ca_path=peer.ca_path,
                server_hostname="localhost",
                timeout=2,
            )
            request = await asyncio.wait_for(peer.received.get(), timeout=1)
            assert_response(response, request)
            assert dict(request.headers)[b":authority"] == b"service.example:8443"
            for name in {name for name, _ in additional_headers}:
                values = [
                    value for field, value in request.headers if field == name.encode()
                ]
                expected = [
                    value.encode()
                    for field, value in additional_headers
                    if field == name
                ]
                assert values == expected
            assert additional_headers == original
