"""Tunnel idle policy across every two-hop pair, contrasted with response bodies."""

from itertools import product
from pathlib import Path
from time import monotonic
from urllib.parse import urlsplit

import pytest

from tests.fixtures.chain_diagnostics import record_chain
from tests.fixtures.http_request import establish_connect_tunnel
from tests.fixtures.matrix_configuration import write_node
from tests.fixtures.matrix_model import CertificateFiles, ChainCase
from tests.fixtures.matrix_origin import ResponseTiming, local_origin
from tests.fixtures.matrix_scenario import run_exchange
from tests.fixtures.ports import get_unique_port

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
    assert 0.4 <= result.elapsed < 5, result.elapsed
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
    assert result.elapsed >= 0.8, result.elapsed
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


def test_tunnel_idle_deadline_starts_before_first_application_byte(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
) -> None:
    """Retain the raw, completely idle CONNECT contract of tunnel_idle_timeout."""
    entry_port, relay_port = get_unique_port(), get_unique_port()
    entry_dir, relay_dir = tmp_path / "entry", tmp_path / "relay"
    relay_config = write_node(relay_dir, "http3", relay_port, matrix_certificates)
    entry_config = write_node(
        entry_dir,
        "http",
        entry_port,
        matrix_certificates,
        next_peer=("http3", relay_port),
        tunnel_idle_timeout="500ms",
    )
    with local_origin("http", matrix_certificates) as origin:
        port = urlsplit(origin.url).port
        assert port is not None
        with record_chain(
            {"entry": entry_dir, "relay": relay_dir}, {"case": "idle-before-data"}
        ) as capture:
            assert capture.start_proxy("relay", relay_config).wait_ready()
            assert capture.start_proxy("entry", entry_config).wait_ready()
            tunnel = establish_connect_tunnel(
                "127.0.0.1", entry_port, "127.0.0.1", port
            )
            assert tunnel is not None
            with tunnel:
                tunnel.settimeout(3)
                started = monotonic()
                assert tunnel.recv(1) == b""
                elapsed = monotonic() - started
                assert 0.4 <= elapsed < 3, elapsed
        assert not origin.requests
