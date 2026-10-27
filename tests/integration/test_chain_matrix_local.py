"""Two-hop local contracts: all 16 protocol pairs and both origin schemes."""

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
        ("GET", "HEAD", "POST"),
    )
    if mode == "tunnel" or "socks5" not in (a, b)
]


@pytest.mark.parametrize("case", _CASES, ids=[case.label for case in _CASES])
def test_two_hop_local_matrix(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    case: ChainCase,
) -> None:
    result = run_exchange(tmp_path, case, "local", matrix_certificates)
    assert result.returncode == 0, result.stderr
    assert result.http_status == 200
    assert len(result.origin_requests) == 1
    request = result.origin_requests[0]
    assert request.method == case.method
    assert request.path == "/matrix"
    if case.method == "POST":
        assert request.body == result.sent_body
        assert result.body == result.sent_body
    elif case.method == "GET":
        assert result.body == b"matrix-origin"
    else:
        assert result.body == b""
    assert len(result.entry_logs) == len(result.relay_logs) == 1
    assert result.entry_logs[0].extensions["upstream.protocol"] == case.relay
    assert result.entry_logs[0].method == (
        "CONNECT" if case.mode == "tunnel" else case.method
    )
    assert result.relay_logs[0].method == result.entry_logs[0].method
    if case.mode == "forward":
        assert result.relay_logs[0].extensions["upstream.protocol"] == case.scheme
