"""Two-hop curl matrix against Cloudflare, including every SOCKS5 relay position."""

from itertools import product
from pathlib import Path

import pytest

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


@pytest.mark.parametrize("case", _CASES, ids=[case.label for case in _CASES])
def test_two_hop_cloudflare_matrix(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    case: ChainCase,
) -> None:
    result = run_exchange(tmp_path, case, "cloudflare", matrix_certificates)
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
