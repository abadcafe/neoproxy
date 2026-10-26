"""Process contracts for DNS binding fallback and Alt-Svc protocol intersection."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.discovery_dns import DnsRecord, discovery_dns
from tests.fixtures.discovery_scenario import curl_forward, direct_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer


@pytest.mark.asyncio
async def test_alias_without_https_records_uses_final_alias_address(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h2")) as peer:
        query = f"_{peer.port}._https.origin.test"
        async with discovery_dns(
            [DnsRecord(name=query, priority=0, target="alias.test")]
        ) as dns:
            with direct_proxy(tmp_path, cert, key, ca, dns_port=dns.port) as entry:
                status, _, body = await curl_forward(
                    entry, f"https://origin.test:{peer.port}/"
                )
                assert status == 200
                assert body == b"h2"
                assert peer.requests[0].headers["alt-used"] == f"alias.test:{peer.port}"
                assert ("alias.test", 1) in dns.queries


@pytest.mark.asyncio
async def test_alt_svc_requires_protocol_overlap_with_https_record(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h2")) as bound:
        async with origin_peer(
            PeerConfig(certificate=cert, key=key, wire="h1")
        ) as origin:
            origin.headers["alt-svc"] = 'h2="advertised.test:443"; ma=60'
            async with discovery_dns(
                [
                    DnsRecord(
                        name="advertised.test", target="bound.test", port=bound.port
                    )
                ]
            ) as dns:
                with direct_proxy(tmp_path, cert, key, ca, dns_port=dns.port) as entry:
                    url = f"https://origin.test:{origin.port}/"
                    assert (await curl_forward(entry, url))[2] == b"h1"
                    assert (await curl_forward(entry, url))[2] == b"h1"
                    assert bound.requests == []


@pytest.mark.asyncio
async def test_unreachable_alternatives_leave_time_for_authority_fallback(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as origin:
        names = {f"slow{index}.test" for index in range(6)}
        origin.headers["alt-svc"] = ", ".join(
            f'h3="{name}:443"; ma=60' for name in sorted(names)
        )
        async with discovery_dns([]) as dns:
            dns.unanswered.update(names)
            with direct_proxy(tmp_path, cert, key, ca, dns_port=dns.port) as entry:
                url = f"https://origin.test:{origin.port}/"
                assert (await curl_forward(entry, url))[2] == b"h1"
                # Optional discovery and probes must share a bounded budget;
                # a list of slow advertisements cannot consume the entire
                # request deadline and suppress a healthy original endpoint.
                async with asyncio.timeout(3):
                    status, _, body = await curl_forward(entry, url)
                assert status == 200
                assert body == b"h1"
