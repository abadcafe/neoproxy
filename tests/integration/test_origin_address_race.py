"""Process contract for fallback across discovered origin addresses."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.discovery_dns import DnsRecord, discovery_dns
from tests.fixtures.discovery_scenario import curl_forward, direct_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer
from tests.fixtures.stream_cleanup import close_writer


@pytest.mark.asyncio
async def test_discovered_origin_races_stalled_tls_address(tmp_path: Path) -> None:
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
        server = await asyncio.start_server(stall, "127.0.0.2", peer.port)
        async with server:
            async with discovery_dns(
                [DnsRecord(name="origin.test", port=peer.port, protocols=("http/1.1",))]
            ) as dns:
                dns.addresses = ("127.0.0.2", "127.0.0.1")
                with direct_proxy(tmp_path, cert, key, ca, dns_port=dns.port) as entry:
                    started = asyncio.get_running_loop().time()
                    status, _, body = await curl_forward(entry, "https://origin.test/")
                    elapsed = asyncio.get_running_loop().time() - started
                    assert attempted.is_set()
                    assert status == 200, (status, body, elapsed)
                    assert body == b"h1"
                    assert elapsed < 2, elapsed
                    assert len(peer.requests) == 1
