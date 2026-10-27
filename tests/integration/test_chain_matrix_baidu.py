"""Two-hop curl matrix against Baidu, including every SOCKS5 relay position."""

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


@pytest.mark.parametrize("case", _CASES, ids=[case.label for case in _CASES])
def test_two_hop_baidu_matrix(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    case: ChainCase,
) -> None:
    result = run_exchange(tmp_path, case, "baidu", matrix_certificates)
    assert result.returncode == 0, result.stderr
    assert result.http_status == 200
    assert len(result.entry_logs) == len(result.relay_logs) == 1
    assert result.entry_logs[0].extensions["upstream.protocol"] == case.relay
    expected_method = "CONNECT" if case.mode == "tunnel" else case.method
    assert result.entry_logs[0].method == result.relay_logs[0].method == expected_method
    if case.method == "GET":
        assert b"baidu" in result.body.lower()
    else:
        assert result.body == b""
