"""Durable evidence and stage timing contracts of the shared chain fixture."""

import shutil
from pathlib import Path

import pytest
from pydantic import BaseModel

from tests.fixtures.access_log_configuration import enable_access_log
from tests.fixtures.chain_diagnostics import record_chain
from tests.fixtures.configuration import JsonValue
from tests.fixtures.forward_scenario import ForwardNode, write_forward_node
from tests.fixtures.http_echo import http_echo_handler
from tests.fixtures.matrix_model import AuthCase, CertificateFiles, ChainCase
from tests.fixtures.matrix_scenario import run_exchange
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import managed_target_servers


class AccessRecord(BaseModel):
    extensions: dict[str, JsonValue]


def access_records(directory: Path) -> list[AccessRecord]:
    return [
        AccessRecord.model_validate_json(line)
        for path in (directory / "logs").glob("access*")
        for line in path.read_text().splitlines()
    ]


def test_proxy_chain_trace_survives_working_directory_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    matrix_certificates: CertificateFiles,
) -> None:
    root = tmp_path / "artifacts"
    monkeypatch.setenv("NEOPROXY_TEST_ARTIFACTS", str(root))
    working = tmp_path / "working"
    result = run_exchange(
        working,
        ChainCase(
            entry="http", relay="http3", mode="forward", scheme="http", method="POST"
        ),
        "local",
        matrix_certificates,
        entry_auth=AuthCase(hop="entry", policy="password"),
        relay_auth=AuthCase(hop="relay", policy="password"),
    )
    assert result.returncode == 0, result.stderr
    shutil.rmtree(working)
    assert not working.exists()
    captures = list(root.iterdir())
    assert len(captures) == 1
    capture = captures[0]
    assert (capture / "entry/curl.body").read_bytes() == result.sent_body
    assert (capture / "curl.metrics.json").is_file()
    entry_logs = "".join(
        path.read_text() for path in (capture / "entry/logs").glob("neoproxy.log*")
    )
    upstream_logs = "".join(
        path.read_text() for path in (capture / "relay/logs").glob("neoproxy.log*")
    )
    assert "H3 response content received" in entry_logs
    assert "H3 request content sent" in entry_logs
    assert "recv_response" in entry_logs and "time.idle" in entry_logs
    assert "origin_connect" not in upstream_logs
    assert "origin TCP connected" not in upstream_logs
    entry_access = access_records(capture / "entry")
    upstream_access = access_records(capture / "relay")
    assert len(entry_access) == len(upstream_access) == 1
    assert (
        entry_access[0].extensions["request.id"]
        == upstream_access[0].extensions["request.id"]
    )
    assert isinstance(upstream_access[0].extensions["upstream.tcp.connect_ms"], int)
    assert "H3 response content sent" in upstream_logs
    assert "shutdown complete" in entry_logs and "shutdown complete" in upstream_logs


def test_chain_capture_records_loopback_tcp_stage_timings(tmp_path: Path) -> None:
    working = tmp_path / "proxy"
    port, origin_port = get_unique_port(), get_unique_port()
    config = write_forward_node(working, ForwardNode(port=port, certificate="", key=""))
    enable_access_log(
        config,
        [
            "request.id",
            "upstream.dns.host",
            "upstream.dns.duration_ms",
            "upstream.dns.addresses",
            "upstream.tcp.connect_ms",
        ],
    )
    with managed_target_servers() as start_target:
        _ = start_target(origin_port, http_echo_handler)
        with record_chain(
            {"entry": working},
            {"case": "local-dns"},
            artifact_root=tmp_path / "artifacts",
        ) as capture:
            directory = capture.directory
            process = capture.start_proxy("entry", config)
            assert process.wait_ready(timeout=2)
            result = capture.run_curl(
                [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--http1.1",
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--noproxy",
                    "",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "20",
                    "--trace-ascii",
                    str(working / "curl.trace"),
                    "--output",
                    str(working / "curl.body"),
                    "--write-out",
                    "%{http_code} %{http_connect}",
                    f"http://127.0.0.1:{origin_port}/",
                ]
            )
            assert result.returncode == 0, result.stderr
            assert result.stdout == "200 000"
    logs = "".join(
        path.read_text() for path in (directory / "entry/logs").glob("neoproxy.log*")
    )
    assert "origin_dns" not in logs and "origin_connect" not in logs
    records = access_records(directory / "entry")
    assert len(records) == 1
    assert "upstream.dns.host" not in records[0].extensions
    assert "upstream.dns.duration_ms" not in records[0].extensions
    assert "upstream.dns.addresses" not in records[0].extensions
    assert isinstance(records[0].extensions["upstream.tcp.connect_ms"], int)


def test_local_matrix_closes_quic_without_shutdown_deadline(
    tmp_path: Path,
    matrix_certificates: CertificateFiles,
) -> None:
    """Ordinary matrix cleanup must finish gracefully without a 3s abort."""
    result = run_exchange(
        tmp_path,
        ChainCase(entry="http3", relay="http3"),
        "local",
        matrix_certificates,
    )
    assert result.returncode == 0, result.stderr
    assert result.body == b"matrix-origin"
    for role in ("entry", "relay"):
        logs = "".join(
            path.read_text()
            for path in (tmp_path / role / "logs").glob("neoproxy.log*")
        )
        assert "shutdown complete" in logs
        assert "transport shutdown timed out" not in logs
