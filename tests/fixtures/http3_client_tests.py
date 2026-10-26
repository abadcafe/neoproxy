"""Wire contracts for complete H3 sessions and certificate verification."""

import ssl
from pathlib import Path

import pytest

from tests.fixtures import http3_client

from .h3_capture import RESPONSE_BODY, capture_peer


@pytest.mark.asyncio
async def test_client_waits_for_fin_after_slow_response_chunk(tmp_path: Path) -> None:
    async with capture_peer(tmp_path, delay=0.4) as peer:
        client = http3_client.H3Client("127.0.0.1", peer.port, ca_path=peer.ca_path)
        try:
            assert await client.connect()
            response = await client.send_request("GET", "/")
            assert response.body == RESPONSE_BODY
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_client_honors_required_certificate_verification_without_custom_ca(
    tmp_path: Path,
) -> None:
    async with capture_peer(tmp_path) as peer:
        client = http3_client.H3Client(
            "127.0.0.1", peer.port, verify_mode=ssl.CERT_REQUIRED
        )
        try:
            assert not await client.connect(), "untrusted certificate was accepted"
        finally:
            await client.close()
