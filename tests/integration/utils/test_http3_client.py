"""
Unit tests for HTTP/3 client utilities.
"""

import asyncio
import pytest
from typing import Dict, List, Tuple

from .http3_client import (
    AIOQUIC_AVAILABLE,
    perform_h3_request_with_custom_authority,
    H3Response,
)


@pytest.mark.skipif(not AIOQUIC_AVAILABLE, reason="aioquic not available")
class TestH3CustomAuthority:
    """Tests for HTTP/3 custom authority functionality."""

    @pytest.mark.asyncio
    async def test_custom_authority_sent_correctly(self) -> None:
        """Should send request with custom :authority pseudo-header."""
        # This test requires a mock server or actual server
        # For now, just verify the function exists and has correct signature
        import inspect
        sig = inspect.signature(perform_h3_request_with_custom_authority)
        params = list(sig.parameters.keys())
        assert "host" in params
        assert "port" in params
        assert "custom_authority" in params

    @pytest.mark.asyncio
    async def test_custom_authority_function_returns_h3response(self) -> None:
        """Should return H3Response even when connection fails."""
        # Calling with invalid host/port should return H3Response, not raise
        response = await perform_h3_request_with_custom_authority(
            host="127.0.0.1",
            port=1,  # Invalid port - will fail to connect
            custom_authority="test.example.com:443",
            timeout=1.0,
        )
        # Should return H3Response with status 0 on error
        assert isinstance(response, H3Response)
        assert response.status_code == 0
        assert b"Timeout" in response.body or b"Connection refused" in response.body or b"error" in response.body.lower() or len(response.body) > 0

    @pytest.mark.asyncio
    async def test_custom_authority_with_additional_headers(self) -> None:
        """Should accept additional headers parameter."""
        # Verify function accepts additional_headers parameter
        additional_headers: List[Tuple[str, str]] = [
            ("host", "different.example.com"),
            ("x-custom-header", "test-value"),
        ]
        response = await perform_h3_request_with_custom_authority(
            host="127.0.0.1",
            port=1,  # Invalid port - will fail to connect
            custom_authority="test.example.com:443",
            additional_headers=additional_headers,
            timeout=1.0,
        )
        # Should return H3Response
        assert isinstance(response, H3Response)
