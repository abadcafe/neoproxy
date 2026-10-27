"""Process contract for fallback across origin addresses."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.discovery_dns import discovery_dns
from tests.fixtures.discovery_scenario import curl_forward, direct_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer
from tests.fixtures.stream_cleanup import close_writer


@pytest.mark.asyncio
async def test_origin_fails_over_after_tls_timeout(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    attempted = asyncio.Event()

    async def stall(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        attempted.set()
        try:
            _ = await reader.read()
        finally:
            await close_writer(writer)

    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as peer:
        server = await asyncio.start_server(stall, "::1", peer.port)
        async with server:
            async with discovery_dns() as dns:
                dns.addresses = ("::1", "127.0.0.1")
                with direct_proxy(
                    tmp_path,
                    cert,
                    key,
                    ca,
                    dns_port=dns.port,
                    tls_handshake_timeout="300ms",
                ) as entry:
                    started = asyncio.get_running_loop().time()
                    status, _, body = await curl_forward(
                        entry, f"https://origin.test:{peer.port}/"
                    )
                    elapsed = asyncio.get_running_loop().time() - started
                    assert attempted.is_set()
                    assert status == 200, (status, body, elapsed)
                    assert body == b"h1"
                    assert elapsed < 2, elapsed
                    assert len(peer.requests) == 1
