"""Two-hop curl matrix against Cloudflare, including every SOCKS5 relay position."""

import asyncio
import socket
from ipaddress import IPv4Address
from itertools import product
from pathlib import Path

import pytest

from tests.fixtures.discovery_dns import discovery_dns
from tests.fixtures.matrix_model import CertificateFiles, ChainCase
from tests.fixtures.matrix_scenario import run_exchange

_CASES = [
    ChainCase(entry=a, relay=b, scheme=s, mode=mode, method=method)
    for a, b, s, mode, method in product(
        ("http", "https", "http3", "socks5"),
        ("http", "https", "http3", "socks5"),
        ("http", "https"),
        ("forward", "tunnel"),
        ("GET", "HEAD"),
    )
    if mode == "tunnel" or "socks5" not in (a, b)
]

_CASES.extend(
    [
        ChainCase(entry=a, relay=b, scheme="https", mode="udp", method=method)
        for a, b, method in product(
            ("http", "https", "http3"), ("http", "https", "http3"), ("GET", "HEAD")
        )
    ]
)


@pytest.fixture
def cloudflare_ipv4_addresses() -> tuple[str, ...]:
    """Use current real A records; never require public IPv6 routing."""
    failure: str | None = None
    try:
        records = socket.getaddrinfo(
            "cloudflare.com", 443, socket.AF_INET, socket.SOCK_DGRAM
        )
    except socket.gaierror as error:
        records = []
        failure = str(error)
    assert records, f"Cloudflare IPv4 DNS lookup failed: {failure}"
    return tuple(sorted({str(IPv4Address(record[4][0])) for record in records}))


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CASES, ids=[case.label for case in _CASES])
async def test_two_hop_cloudflare_matrix(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    case: ChainCase,
    cloudflare_ipv4_addresses: tuple[str, ...],
) -> None:
    # Both proxy nodes resolve through a test DNS endpoint containing
    # only real public A records. --ipv4 alone cannot constrain the
    # proxy's own DNS lookup, especially for CONNECT-UDP.
    async with discovery_dns() as dns:
        dns.addresses = cloudflare_ipv4_addresses
        result = await asyncio.to_thread(
            run_exchange,
            tmp_path,
            case,
            "cloudflare",
            matrix_certificates,
            dns_servers=(f"127.0.0.1:{dns.port}",),
        )
        assert ("cloudflare.com", 1) in dns.queries, dns.queries
    # A selected Cloudflare A endpoint can reset TCP after CONNECT
    # succeeds. A TLS proxy then exposes that origin reset as an unexpected
    # EOF. The saved relay tunnel log identifies the remote socket and error;
    # this external failure must remain visible, without an exchange retry.
    # This live UDP case also depends on the selected Cloudflare A
    # address responding on UDP/443. Local 101/200 tunnel negotiation
    # does not prove that reachability. Keep failures visible and use
    # the saved curl trace/socket observations to distinguish the two;
    # do not retry the exchange or weaken its success assertion.
    assert result.returncode == 0, result.stderr
    assert result.http_status == 301
    assert len(result.entry_logs) == len(result.relay_logs) == 1
    assert result.entry_logs[0].extensions["upstream.protocol"] == case.relay
    expected_method = (
        "CONNECT"
        if case.mode == "tunnel" or (case.mode == "udp" and case.entry == "http3")
        else case.method
    )
    if case.mode == "udp":
        assert result.entry_logs[0].method == (
            "CONNECT" if case.entry == "http3" else "GET"
        )
        assert result.relay_logs[0].method == (
            "CONNECT" if case.relay == "http3" else "GET"
        )
    else:
        assert (
            result.entry_logs[0].method
            == result.relay_logs[0].method
            == expected_method
        )
    if case.method == "GET":
        assert b"cloudflare" in result.body.lower()
    else:
        assert result.body == b""
