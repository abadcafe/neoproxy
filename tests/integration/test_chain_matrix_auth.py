"""Authentication at either hop, across every applicable protocol pair."""

from itertools import product
from pathlib import Path

import pytest

from tests.fixtures.matrix_model import AuthCase, CertificateFiles, ChainCase
from tests.fixtures.matrix_scenario import run_exchange

_CASES = [
    (ChainCase(entry=a, relay=b), AuthCase(hop=hop, policy=policy, fault=fault))
    for a, b, hop, policy, fault in product(
        ("http", "https", "http3", "socks5"),
        ("http", "https", "http3", "socks5"),
        ("entry", "relay"),
        ("password", "certificate", "both"),
        (
            "none",
            "missing_password",
            "wrong_password",
            "missing_certificate",
            "wrong_certificate",
        ),
    )
    if (policy == "password" or (a if hop == "entry" else b) in ("https", "http3"))
    and (
        fault == "none"
        or ("password" in fault and policy != "certificate")
        or ("certificate" in fault and policy != "password")
    )
]


@pytest.mark.parametrize(
    "case,auth",
    _CASES,
    ids=[
        f"{case.entry}-{case.relay}-{auth.hop}-{auth.policy}-{auth.fault}"
        for case, auth in _CASES
    ],
)
def test_two_hop_authentication(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    case: ChainCase,
    auth: AuthCase,
) -> None:
    result = run_exchange(
        tmp_path,
        case,
        "local",
        matrix_certificates,
        entry_auth=auth if auth.hop == "entry" else None,
        relay_auth=auth if auth.hop == "relay" else None,
    )
    if auth.fault == "none":
        assert result.returncode == 0, result.stderr
        assert result.http_status == 200
        assert result.body == b"matrix-origin"
        assert len(result.origin_requests) == 1
        assert len(result.entry_logs) == len(result.relay_logs) == 1
    else:
        assert result.returncode != 0
        assert result.http_status == 0
        assert not result.origin_requests
        if auth.hop == "relay":
            assert len(result.entry_logs) == 1
            assert result.entry_logs[0].status == (
                403
                if auth.fault == "missing_certificate" or case.relay == "socks5"
                else 502
            )
        elif "password" in auth.fault:
            assert len(result.entry_logs) == 1
            assert result.entry_logs[0].status == 407
            # curl's experimental H3 proxy backend does not populate
            # http_connect on rejected streams. The server log is authoritative.
            if case.entry in ("http", "https"):
                assert result.connect_status == 407
        if auth.hop == "entry":
            assert not result.relay_logs
