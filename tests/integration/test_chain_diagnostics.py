"""Timeout evidence is an executable contract of the original chain fixture."""

from pathlib import Path

import pytest
from pydantic import BaseModel

from tests.fixtures.access_log_configuration import enable_access_log
from tests.fixtures.chain_diagnostics import record_chain
from tests.fixtures.chain_scenario import ChainRequest, run_proxy_chain_test
from tests.fixtures.configuration import JsonValue, StringMap
from tests.fixtures.forward_scenario import ForwardNode, write_forward_node
from tests.fixtures.http_echo import http_echo_handler
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
    shared_test_certs: StringMap,
) -> None:
    root = tmp_path / "artifacts"
    monkeypatch.setenv("NEOPROXY_TEST_ARTIFACTS", str(root))
    entry, upstream = tmp_path / "entry", tmp_path / "upstream"
    entry.mkdir()
    upstream.mkdir()
    run_proxy_chain_test(
        entry_type="http",
        upstream_auth="password",
        target_type="mock",
        http_port=get_unique_port(),
        h3_port=get_unique_port(),
        target_port=get_unique_port(),
        temp_dir1=str(upstream),
        temp_dir2=str(entry),
        shared_test_certs=shared_test_certs,
        case=ChainRequest(mode="forward", scheme="http", method="POST"),
    )
    assert not entry.exists() and not upstream.exists()
    captures = list(root.iterdir())
    assert len(captures) == 1
    capture = captures[0]
    assert (capture / "entry/curl.body").read_bytes() == b"test_data_chain"
    assert (capture / "curl.metrics.json").is_file()
    entry_logs = "".join(
        path.read_text() for path in (capture / "entry/logs").glob("neoproxy.log*")
    )
    upstream_logs = "".join(
        path.read_text() for path in (capture / "upstream/logs").glob("neoproxy.log*")
    )
    assert "H3 response content received" in entry_logs
    assert "H3 request content sent" in entry_logs
    assert "recv_response" in entry_logs and "time.idle" in entry_logs
    assert "origin_connect" not in upstream_logs
    assert "origin TCP connected" not in upstream_logs
    entry_access = access_records(capture / "entry")
    upstream_access = access_records(capture / "upstream")
    assert len(entry_access) == len(upstream_access) == 1
    assert (
        entry_access[0].extensions["request.id"]
        == upstream_access[0].extensions["request.id"]
    )
    assert isinstance(upstream_access[0].extensions["upstream.tcp.connect_ms"], int)
    assert "H3 response content sent" in upstream_logs
    assert "shutdown complete" in entry_logs and "shutdown complete" in upstream_logs


def test_chain_capture_records_system_dns_and_tcp_stage_timings(tmp_path: Path) -> None:
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
                    f"http://localhost:{origin_port}/",
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
    assert records[0].extensions["upstream.dns.host"] == "localhost"
    assert isinstance(records[0].extensions["upstream.dns.duration_ms"], int)
    assert isinstance(records[0].extensions["upstream.dns.addresses"], list)
    assert isinstance(records[0].extensions["upstream.tcp.connect_ms"], int)
