"""Wire contracts for isolated HTTP/3 request scenarios."""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import aioquic.asyncio.client as quic_client
import pytest
from aioquic.h3.events import HeadersReceived

from tests.fixtures import h3_request
from tests.fixtures.http3_client import H3Response

from .h3_capture import RESPONSE_BODY, capture_peer


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
            response = await h3_request.perform_h3_request_with_custom_authority(
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

        response = await h3_request.perform_h3_request_with_custom_authority(
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
            response = await h3_request.perform_h3_request_with_custom_authority(
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
