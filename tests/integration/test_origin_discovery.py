"""curl contracts for protocol discovery owned by the terminal direct client."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_server_cert, generate_test_certificates
from tests.fixtures.discovery_dns import DnsRecord, discovery_dns
from tests.fixtures.discovery_scenario import curl_forward, direct_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer


@pytest.mark.asyncio
@pytest.mark.parametrize("chain", [False, True], ids=["direct", "http-chain"])
async def test_alt_svc_upgrades_to_h3_and_reuses_connection(
    tmp_path: Path, chain: bool
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=60'
            with direct_proxy(tmp_path, cert, key, ca, chain=chain) as entry:
                url = f"https://127.0.0.1:{h1.port}/resource?q=1"
                for expected in [b"h1", b"h3", b"h3"]:
                    status, headers, body = await curl_forward(entry, url)
                    assert status == 200, (headers, body, h1.requests, h3.requests)
                    assert b"alt-svc:" not in headers.lower()
                    assert body == expected
                assert len(h1.requests) == 1
                assert len(h3.requests) == 2
                assert h3.requests[0].connection == h3.requests[1].connection
                assert h3.requests[0].headers[":authority"] == f"127.0.0.1:{h1.port}"
                assert h3.requests[0].headers[":path"] == "/resource?q=1"
                assert h3.requests[0].headers["alt-used"] == f"127.0.0.1:{h3.port}"


@pytest.mark.asyncio
async def test_direct_https_negotiates_h2_and_reuses_connection(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h2")) as h2:
        with direct_proxy(tmp_path, cert, key, ca) as entry:
            for payload in [b"first", b"second"]:
                status, _, body = await curl_forward(
                    entry, f"https://127.0.0.1:{h2.port}/upload", payload
                )
                assert status == 200
                assert body == payload
            assert len(h2.requests) == 2
            assert h2.requests[0].connection == h2.requests[1].connection


@pytest.mark.asyncio
@pytest.mark.parametrize("expiry", ["clear", "zero", "expired"])
async def test_alt_svc_cache_expiry_returns_to_original_endpoint(
    tmp_path: Path, expiry: str
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=1'
            with direct_proxy(tmp_path, cert, key, ca) as entry:
                url = f"https://127.0.0.1:{h1.port}/"
                assert (await curl_forward(entry, url))[2] == b"h1"
                if expiry == "expired":
                    await asyncio.sleep(1.1)
                else:
                    h3.headers["alt-svc"] = (
                        "clear" if expiry == "clear" else f'h3=":{h3.port}"; ma=0'
                    )
                    assert (await curl_forward(entry, url))[2] == b"h3"
                assert (await curl_forward(entry, url))[2] == b"h1"


@pytest.mark.asyncio
async def test_failed_h3_handshake_falls_back_before_post_is_sent(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
        # This TCP port has no QUIC listener.
        h1.headers["alt-svc"] = f'h3=":{h1.port}"; ma=60'
        with direct_proxy(tmp_path, cert, key, ca) as entry:
            url = f"https://127.0.0.1:{h1.port}/"
            assert (await curl_forward(entry, url))[0] == 200
            status, _, body = await curl_forward(entry, url, b"only-once")
            assert status == 200
            assert body == b"only-once"
            assert [r.body for r in h1.requests] == [b"", b"only-once"]


@pytest.mark.asyncio
@pytest.mark.parametrize("alias", [False, True], ids=["service", "alias"])
async def test_dns_https_selects_h3_on_first_request(
    tmp_path: Path, alias: bool
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test", "127.0.0.1"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        owner = "alias.test" if alias else "origin.test"
        records = [DnsRecord(name=owner, target="backend.test", port=h3.port)]
        if alias:
            records.insert(0, DnsRecord(name="origin.test", priority=0, target=owner))
        async with discovery_dns(records) as dns:
            with direct_proxy(tmp_path, cert, key, ca, dns_port=dns.port) as entry:
                for payload in [b"dns-first", b"dns-reused"]:
                    status, _, body = await curl_forward(
                        entry, "https://origin.test/", payload
                    )
                    assert status == 200
                    assert body == payload
                assert len(h3.requests) == 2
                assert h3.requests[0].headers[":authority"] == "origin.test"
                assert h3.requests[0].connection == h3.requests[1].connection
                assert ("origin.test", 65) in dns.queries


@pytest.mark.asyncio
async def test_dns_https_unknown_mandatory_falls_back_to_original(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h2")) as h2:
        name = f"_{h2.port}._https.origin.test"
        async with discovery_dns(
            [DnsRecord(name=name, port=h2.port, mandatory=(65400,))]
        ) as dns:
            with direct_proxy(tmp_path, cert, key, ca, dns_port=dns.port) as entry:
                status, _, body = await curl_forward(
                    entry, f"https://origin.test:{h2.port}/"
                )
                assert status == 200
                assert body == b"h2"


@pytest.mark.asyncio
async def test_dns_https_ttl_expiry_discovers_replacement(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as first:
        async with origin_peer(
            PeerConfig(certificate=cert, key=key, wire="h3")
        ) as second:
            records = [DnsRecord(name="origin.test", port=first.port, ttl=1)]
            async with discovery_dns(records) as dns:
                with direct_proxy(tmp_path, cert, key, ca, dns_port=dns.port) as entry:
                    assert (await curl_forward(entry, "https://origin.test/"))[0] == 200
                    records[0] = DnsRecord(name="origin.test", port=second.port, ttl=1)
                    await asyncio.sleep(1.1)
                    assert (await curl_forward(entry, "https://origin.test/"))[0] == 200
                    assert len(first.requests) == len(second.requests) == 1


@pytest.mark.asyncio
async def test_concurrent_h3_requests_share_first_connection(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=60'
            with direct_proxy(tmp_path, cert, key, ca) as entry:
                url = f"https://127.0.0.1:{h1.port}/"
                assert (await curl_forward(entry, url))[0] == 200
                results = await asyncio.gather(
                    *(
                        curl_forward(entry, url, f"body-{index}".encode())
                        for index in range(6)
                    )
                )
                assert all(status == 200 for status, _, _ in results)
                assert {body for _, _, body in results} == {
                    f"body-{index}".encode() for index in range(6)
                }
                assert len({item.connection for item in h3.requests}) == 1


@pytest.mark.asyncio
async def test_h3_wrong_certificate_name_falls_back_without_sending_request(
    tmp_path: Path,
) -> None:
    cert, key, ca, ca_key = generate_test_certificates(str(tmp_path))
    wrong_cert, wrong_key = generate_server_cert(
        str(tmp_path), ca, ca_key, ["wrong.test"], cert_name="wrong"
    )
    async with origin_peer(
        PeerConfig(certificate=wrong_cert, key=wrong_key, wire="h3")
    ) as h3:
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=60'
            with direct_proxy(tmp_path, cert, key, ca) as entry:
                url = f"https://127.0.0.1:{h1.port}/"
                assert (await curl_forward(entry, url))[0] == 200
                assert (await curl_forward(entry, url, b"private-body"))[
                    2
                ] == b"private-body"
                assert h3.requests == []
                assert len(h1.requests) == 2


@pytest.mark.asyncio
async def test_h3_request_failure_does_not_replay_post_to_origin(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        h3.abort_response = True
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=60'
            with direct_proxy(tmp_path, cert, key, ca) as entry:
                url = f"https://127.0.0.1:{h1.port}/"
                assert (await curl_forward(entry, url))[0] == 200
                status, _, _ = await curl_forward(entry, url, b"committed-post")
                assert status == 502
                assert [item.body for item in h3.requests] == [b"committed-post"]
                assert len(h1.requests) == 1


@pytest.mark.asyncio
async def test_h3_pool_closes_idle_connections_without_another_request(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=60'
            with direct_proxy(tmp_path, cert, key, ca, idle_timeout="100ms") as entry:
                url = f"https://127.0.0.1:{h1.port}/"
                assert (await curl_forward(entry, url))[0] == 200
                assert (await curl_forward(entry, url))[2] == b"h3"
                async with asyncio.timeout(2):
                    while h3.closed_connections == 0:
                        await asyncio.sleep(0.02)
                assert (await curl_forward(entry, url))[2] == b"h3"
                assert len({item.connection for item in h3.requests}) == 2


@pytest.mark.asyncio
async def test_alt_svc_endpoint_respects_dns_https_binding(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(
        PeerConfig(certificate=cert, key=key, wire="h3")
    ) as advertised:
        async with origin_peer(
            PeerConfig(certificate=cert, key=key, wire="h3")
        ) as bound:
            async with origin_peer(
                PeerConfig(certificate=cert, key=key, wire="h1")
            ) as h1:
                h1.headers["alt-svc"] = f'h3=":{advertised.port}"; ma=60'
                name = f"_{advertised.port}._https.origin.test"
                async with discovery_dns(
                    [DnsRecord(name=name, target="backend.test", port=bound.port)]
                ) as dns:
                    with direct_proxy(
                        tmp_path, cert, key, ca, dns_port=dns.port
                    ) as entry:
                        url = f"https://origin.test:{h1.port}/"
                        assert (await curl_forward(entry, url))[2] == b"h1"
                        assert (await curl_forward(entry, url))[2] == b"h3"
                        assert len(advertised.requests) == 0
                        assert len(bound.requests) == 1
                        assert (
                            bound.requests[0].headers[":authority"]
                            == f"origin.test:{h1.port}"
                        )


@pytest.mark.asyncio
@pytest.mark.parametrize("max_idle", [0, 1])
async def test_h3_pool_respects_idle_reuse_limit(tmp_path: Path, max_idle: int) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=60'
            with direct_proxy(
                tmp_path, cert, key, ca, max_idle_per_host=max_idle
            ) as entry:
                url = f"https://127.0.0.1:{h1.port}/"
                assert (await curl_forward(entry, url))[0] == 200
                for _ in range(2):
                    assert (await curl_forward(entry, url))[2] == b"h3"
                assert len({item.connection for item in h3.requests}) == (
                    2 if max_idle == 0 else 1
                )


@pytest.mark.asyncio
async def test_h3_pool_retains_active_response_past_idle_timeout(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as h3:
        h3.response_delay = 0.4
        async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as h1:
            h1.headers["alt-svc"] = f'h3=":{h3.port}"; ma=60'
            with direct_proxy(tmp_path, cert, key, ca, idle_timeout="100ms") as entry:
                url = f"https://127.0.0.1:{h1.port}/"
                assert (await curl_forward(entry, url))[0] == 200
                pending = asyncio.create_task(
                    curl_forward(entry, url, b"delayed-response")
                )
                await asyncio.sleep(0.25)
                assert h3.closed_connections == 0
                status, _, body = await pending
                assert status == 200
                assert body == b"delayed-response"
