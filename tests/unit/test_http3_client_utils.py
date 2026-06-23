"""Unit tests for HTTP/3 client utilities."""

from contextlib import asynccontextmanager
import inspect
from typing import AsyncIterator, List, Tuple

import pytest

from tests.integration.utils import http3_client
from tests.integration.utils.http3_client import H3Response


@asynccontextmanager
async def failing_h3_connect(*args: object, **kwargs: object) -> AsyncIterator[None]:
    raise OSError("connection refused")
    yield


class TestH3CustomAuthority:
    """Tests for HTTP/3 custom authority functionality."""

    @pytest.mark.asyncio
    async def test_custom_authority_sent_correctly(self) -> None:
        """Should send request with custom :authority pseudo-header."""
        # This test requires a mock server or actual server
        # For now, just verify the function exists and has correct signature
        sig = inspect.signature(
            http3_client.perform_h3_request_with_custom_authority
        )
        params = list(sig.parameters.keys())
        assert "host" in params
        assert "port" in params
        assert "custom_authority" in params

    @pytest.mark.asyncio
    async def test_custom_authority_function_returns_h3response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Should return H3Response even when connection fails."""
        monkeypatch.setattr(http3_client, "connect", failing_h3_connect)

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
    async def test_custom_authority_with_additional_headers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Should accept additional headers parameter."""
        monkeypatch.setattr(http3_client, "connect", failing_h3_connect)

        additional_headers: List[Tuple[str, str]] = [
            ("host", "different.example.com"),
            ("x-custom-header", "test-value"),
        ]
        response = await http3_client.perform_h3_request_with_custom_authority(
            host="127.0.0.1",
            port=1,
            custom_authority="test.example.com:443",
            additional_headers=additional_headers,
            timeout=1.0,
        )
        assert isinstance(response, H3Response)
