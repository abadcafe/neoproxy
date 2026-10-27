"""curl contracts for resolved peer scheduling, DNS refresh and passive health."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.discovery_dns import discovery_dns
from tests.fixtures.discovery_scenario import curl_forward
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer


def configuration(ca: str, dns_port: int, addresses: list[ConfigDict]) -> ConfigDict:
    return {
        "server_threads": 1,
        "plugins": {
            "http_upstream": {
                "certificates": {"server_ca_path": ca},
                "dns_servers": [f"127.0.0.1:{dns_port}"],
                "dns_resolve_timeout": "200ms",
                "address_protocol": "http3" if not addresses else "https",
                "dns_refresh_retry_interval": "500ms",
                "address_fail_timeout": "500ms",
                "upstream_request_timeout": "300ms",
                "tcp_keep_alive_time": "30s",
                "tcp_keep_alive_interval": "5s",
                "tcp_keep_alive_retries": 3,
                "upstreams": [{"name": "main", "addresses": list(addresses)}],
            }
        },
        "listeners": [{"name": "main", "kind": "http"}],
        "services": [
            {
                "name": "main",
                "kind": "http_upstream.upstream",
                "args": {"upstream": "main"},
            }
        ],
        "servers": [{"name": "main", "listeners": ["main"], "service": "main"}],
    }


@pytest.mark.asyncio
async def test_all_resolved_ips_inherit_address_weight(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["a.test", "b.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as a4:
        async with origin_peer(
            PeerConfig(certificate=cert, key=key, wire="h1", host="::1", port=a4.port)
        ) as a6:
            async with origin_peer(
                PeerConfig(certificate=cert, key=key, wire="h1")
            ) as b:
                async with discovery_dns() as dns:
                    dns.hosts = {
                        "a.test": ("::1", "127.0.0.1"),
                        "b.test": ("127.0.0.1",),
                    }
                    config = configuration(
                        ca,
                        dns.port,
                        [
                            {"address": f"a.test:{a4.port}", "weight": 2},
                            {"address": f"b.test:{b.port}", "weight": 1},
                        ],
                    )
                    with running_proxy(tmp_path, config) as proxy:
                        for _ in range(10):
                            assert (
                                await curl_forward(proxy.port, "http://target.test/")
                            )[0] == 200
                    assert [len(peer.requests) for peer in (a4, a6, b)] == [4, 4, 2]
                    assert all(
                        request.alpn == "http/1.1"
                        for peer in (a4, a6, b)
                        for request in peer.requests
                    )


@pytest.mark.asyncio
@pytest.mark.parametrize("direct", [True, False])
async def test_dns_ttl_stale_on_error_and_refresh_retry(
    tmp_path: Path, direct: bool
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as old:
        async with origin_peer(
            PeerConfig(certificate=cert, key=key, wire="h1", host="::1", port=old.port)
        ) as new:
            async with discovery_dns() as dns:
                dns.ttl = 1
                addresses: list[ConfigDict] = (
                    [] if direct else [{"address": f"origin.test:{old.port}"}]
                )
                with running_proxy(
                    tmp_path, configuration(ca, dns.port, addresses)
                ) as proxy:
                    url = (
                        f"https://origin.test:{old.port}/"
                        if direct
                        else "http://target.test/"
                    )
                    assert (await curl_forward(proxy.port, url))[0] == 200
                    queries = len(dns.queries)
                    dns.addresses = ("::1",)
                    assert (await curl_forward(proxy.port, url))[0] == 200
                    assert len(dns.queries) == queries
                    assert len(old.requests) == 2 and not new.requests
                    await asyncio.sleep(1.1)
                    dns.failure = True
                    assert (await curl_forward(proxy.port, url))[0] == 200
                    queries = len(dns.queries)
                    assert queries > 2
                    assert (await curl_forward(proxy.port, url))[0] == 200
                    assert len(dns.queries) == queries
                    assert len(old.requests) == 4 and not new.requests
                    dns.failure = False
                    await asyncio.sleep(0.6)
                    assert (await curl_forward(proxy.port, url))[0] == 200
                    assert len(new.requests) == 1
                    assert len(old.requests) == 4
                    assert all(kind in (1, 28) for _, kind in dns.queries)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["reset", "timeout", "status", "invalid_header"])
async def test_passive_health_counts_transport_failures_only(
    tmp_path: Path, failure: str
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["a.test", "b.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as bad:
        async with origin_peer(
            PeerConfig(certificate=cert, key=key, wire="h1")
        ) as good:
            async with discovery_dns() as dns:
                bad.abort_response = failure == "reset"
                bad.invalid_response = failure == "invalid_header"
                bad.header_delay = 0.8 if failure == "timeout" else 0
                bad.status = 503 if failure == "status" else 200
                config = configuration(
                    ca,
                    dns.port,
                    [
                        {"address": f"a.test:{bad.port}"},
                        {"address": f"b.test:{good.port}"},
                    ],
                )
                with running_proxy(tmp_path, config) as proxy:
                    first, _, _ = await curl_forward(
                        proxy.port, "http://target.test/", b"one-shot"
                    )
                    assert (
                        first
                        == {
                            "reset": 502,
                            "timeout": 504,
                            "status": 503,
                            "invalid_header": 502,
                        }[failure]
                    )
                    # Committed POST is never replayed onto another node.
                    assert len(bad.requests) == 1 and not good.requests
                    for _ in range(3):
                        _ = await curl_forward(proxy.port, "http://target.test/")
                    if failure in ("status", "invalid_header"):
                        assert len(bad.requests) == 2 and len(good.requests) == 2
                    else:
                        assert len(bad.requests) == 1 and len(good.requests) == 3
                        bad.abort_response = False
                        bad.header_delay = 0
                        await asyncio.sleep(0.6)
                        for _ in range(4):
                            assert (
                                await curl_forward(proxy.port, "http://target.test/")
                            )[0] == 200
                        assert len(bad.requests) > 1


@pytest.mark.asyncio
async def test_concurrent_dns_refresh_is_shared_even_with_zero_ttl(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as peer:
        async with discovery_dns() as dns:
            dns.ttl = 0
            dns.response_delay = 0.1
            config = configuration(ca, dns.port, [])
            with running_proxy(tmp_path, config) as proxy:
                url = f"https://origin.test:{peer.port}/"
                responses = await asyncio.gather(
                    *(curl_forward(proxy.port, url) for _ in range(6))
                )
                assert all(status == 200 for status, _, _ in responses)
                assert len(dns.queries) == 2
                assert (await curl_forward(proxy.port, url))[0] == 200
                assert len(dns.queries) == 4
