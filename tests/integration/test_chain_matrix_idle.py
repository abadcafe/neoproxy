"""Tunnel idle policy across every two-hop pair, contrasted with response bodies."""

from itertools import product
from pathlib import Path

import pytest

from tests.fixtures.matrix_model import CertificateFiles, ChainCase
from tests.fixtures.matrix_origin import ResponseTiming
from tests.fixtures.matrix_scenario import run_exchange

_PAIRS = list(product(("http", "https", "http3", "socks5"), repeat=2))


@pytest.mark.parametrize("entry,relay", _PAIRS)
def test_idle_tunnel_closes_before_curl_deadline(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    entry: str,
    relay: str,
) -> None:
    case = ChainCase.model_validate({"entry": entry, "relay": relay, "scheme": "http"})
    result = run_exchange(
        tmp_path,
        case,
        "local",
        matrix_certificates,
        origin_timing=ResponseTiming(body_delay=1.3),
        tunnel_idle_timeout="500ms",
    )
    assert result.http_status == 200
    assert result.returncode != 0 and result.returncode != 28, result.stderr
    assert result.body == b""
    assert len(result.origin_requests) == 1


@pytest.mark.parametrize("entry,relay", _PAIRS)
def test_active_tunnel_outlives_idle_interval(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    entry: str,
    relay: str,
) -> None:
    case = ChainCase.model_validate({"entry": entry, "relay": relay, "scheme": "http"})
    result = run_exchange(
        tmp_path,
        case,
        "local",
        matrix_certificates,
        origin_timing=ResponseTiming(byte_interval=0.08),
        tunnel_idle_timeout="500ms",
    )
    assert result.returncode == 0, result.stderr
    assert result.body == b"matrix-origin"


@pytest.mark.parametrize(
    "entry,relay", [(a, b) for a, b in _PAIRS if "socks5" not in (a, b)]
)
def test_forward_response_body_ignores_tunnel_idle_timeout(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
    entry: str,
    relay: str,
) -> None:
    case = ChainCase.model_validate(
        {"entry": entry, "relay": relay, "scheme": "http", "mode": "forward"}
    )
    result = run_exchange(
        tmp_path,
        case,
        "local",
        matrix_certificates,
        origin_timing=ResponseTiming(body_delay=1.3),
        tunnel_idle_timeout="500ms",
    )
    assert result.returncode == 0, result.stderr
    assert result.body == b"matrix-origin"
