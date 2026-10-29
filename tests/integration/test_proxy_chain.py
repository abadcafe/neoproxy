"""Authentication isolation between two simultaneously protected hops.

Transport/method/scheme coverage and single-hop rejection belong to
chain_matrix_local, chain_matrix_cloudflare and chain_matrix_auth. These cases
retain the old proxy_chain contract that both hops authenticate independently,
including forwarding POST bodies and rejecting either hop's credentials.
"""

from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.matrix_model import (
    AuthCase,
    CertificateFiles,
    ChainCase,
    ProxyProtocol,
    RequestMode,
)
from tests.fixtures.matrix_scenario import run_exchange

_ROUTES: list[tuple[ProxyProtocol, RequestMode]] = [
    ("http", "forward"),
    ("http", "tunnel"),
    ("https", "forward"),
    ("http3", "forward"),
    ("socks5", "tunnel"),
]

_CASES = [
    ChainCase(entry=entry, relay="http3", scheme=scheme, mode=mode, method="POST")
    for entry, mode in _ROUTES
    for scheme in ("http", "https")
]


@pytest.mark.parametrize("case", _CASES, ids=[case.label for case in _CASES])
@pytest.mark.parametrize("policy", ["password", "certificate"])
def test_chain_authenticates_both_hops(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    case: ChainCase,
    policy: Literal["password", "certificate"],
) -> None:
    result = run_exchange(
        tmp_path,
        case,
        "local",
        matrix_certificates,
        entry_auth=AuthCase(hop="entry", policy="password"),
        relay_auth=AuthCase(hop="relay", policy=policy),
    )
    assert result.returncode == 0, result.stderr
    assert result.http_status == 200
    assert result.connect_status == (
        200 if case.entry == "http" and case.mode == "tunnel" else 0
    )
    assert len(result.origin_requests) == 1
    assert result.origin_requests[0].body == result.sent_body == result.body
    assert len(result.entry_logs) == len(result.relay_logs) == 1
    trace = (tmp_path / "entry/curl.trace").read_text()
    if case.mode == "forward":
        assert "POST http" in trace
    elif case.entry == "http":
        assert "CONNECT 127.0.0.1:" in trace


@pytest.mark.parametrize("mode", ["forward", "tunnel"])
@pytest.mark.parametrize("hop", ["entry", "relay"])
@pytest.mark.parametrize("fault", ["missing_password", "wrong_password"])
def test_chain_rejects_one_invalid_password_with_other_hop_authenticated(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    mode: Literal["forward", "tunnel"],
    hop: Literal["entry", "relay"],
    fault: Literal["missing_password", "wrong_password"],
) -> None:
    result = run_exchange(
        tmp_path,
        ChainCase(entry="http", relay="http3", mode=mode),
        "local",
        matrix_certificates,
        entry_auth=AuthCase(
            hop="entry",
            policy="password",
            fault=fault if hop == "entry" else "none",
        ),
        relay_auth=AuthCase(
            hop="relay",
            policy="password",
            fault=fault if hop == "relay" else "none",
        ),
    )
    assert not result.origin_requests
    assert len(result.entry_logs) == 1
    assert result.entry_logs[0].status == (
        407 if hop == "entry" or mode == "forward" else 502
    )
    if hop == "entry":
        assert not result.relay_logs
    else:
        assert len(result.relay_logs) == 1
        assert result.relay_logs[0].status == 407
