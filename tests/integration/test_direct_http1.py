"""curl contracts for HTTP/1.1 origin forwarding and connection reuse."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.discovery_dns import discovery_dns
from tests.fixtures.discovery_scenario import curl_forward, direct_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer


@pytest.mark.asyncio
@pytest.mark.parametrize("chain", [False, True])
@pytest.mark.parametrize("alpn", [("http/1.1",), ()])
async def test_direct_https_uses_http1_and_reuses_connection(
    tmp_path: Path, chain: bool, alpn: tuple[str, ...]
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(
        PeerConfig(certificate=cert, key=key, wire="h1", alpn=alpn)
    ) as peer:
        peer.headers["alt-svc"] = 'h3=":443"; ma=60'
        async with discovery_dns() as dns:
            with direct_proxy(
                tmp_path, cert, key, ca, chain=chain, dns_port=dns.port
            ) as entry:
                for payload in [None, b"payload"]:
                    status, headers, body = await curl_forward(
                        entry, f"https://origin.test:{peer.port}/path?q=1", payload
                    )
                    assert status == 200
                    assert body == (payload or b"h1")
                    assert b"alt-svc:" not in headers.lower()
                assert len(peer.requests) == 2
                assert {request.alpn for request in peer.requests} == {
                    "http/1.1" if alpn else None
                }
                assert len({request.connection for request in peer.requests}) == 1
                assert all(
                    "alt-used" not in request.headers for request in peer.requests
                )
                assert dns.queries
                assert all(kind in (1, 28) for _, kind in dns.queries)


@pytest.mark.asyncio
@pytest.mark.parametrize("max_idle", [0, 1])
async def test_direct_http1_respects_idle_pool_limits(
    tmp_path: Path, max_idle: int
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as peer:
        with direct_proxy(
            tmp_path, cert, key, ca, idle_timeout="50ms", max_idle_per_host=max_idle
        ) as entry:
            for _ in range(2):
                status, _, body = await curl_forward(
                    entry, f"https://127.0.0.1:{peer.port}/"
                )
                assert status == 200 and body == b"h1"
                await asyncio.sleep(0.1)
            assert len(peer.requests) == 2
            assert len({request.connection for request in peer.requests}) == 2
