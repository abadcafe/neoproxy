"""Durable diagnostics without changing a transfer's result or deadline."""

import socket
import subprocess
import sys
import threading
from pathlib import Path

import psutil
from pydantic import BaseModel, TypeAdapter

from tests.fixtures.chain_diagnostics import record_chain
from tests.fixtures.http_configuration import create_echo_config
from tests.fixtures.http_echo import read_http_request
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import managed_target_servers


class CurlMetrics(BaseModel):
    size_download: int
    time_total: float


class ProcessEvidence(BaseModel):
    processes: dict[str, int]
    exit_codes: dict[str, int | None]
    failure: str | None


def test_record_chain_keeps_logs_and_exact_curl_status(tmp_path: Path) -> None:
    working = tmp_path / "working"
    working.mkdir()
    payload = working / "payload"
    _ = payload.write_bytes(b"diagnostic payload")
    port = get_unique_port()
    with record_chain(
        {"entry": working}, {"case": "local"}, artifact_root=tmp_path / "artifacts"
    ) as capture:
        directory = capture.directory
        process = capture.start_proxy("entry", create_echo_config(port, str(working)))
        assert process.wait_ready()
        result = capture.run_curl(
            [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "20",
                "--trace-ascii",
                str(working / "curl.trace"),
                "--output",
                str(working / "curl.body"),
                "--write-out",
                "%{http_code} %{http_connect}",
                payload.as_uri(),
            ]
        )
        assert result.returncode == 0
        assert result.stdout == "000 000"
    assert process.poll() is not None
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed
    assert (directory / "entry/curl.body").read_bytes() == b"diagnostic payload"
    assert (directory / "entry/curl.trace").read_text()
    assert list((directory / "entry/logs").glob("neoproxy.log*"))
    assert (directory / "entry/stdout.log").is_file()
    assert (directory / "entry/stderr.log").is_file()
    assert (directory / "sockets.jsonl").is_file()
    metrics = CurlMetrics.model_validate_json(
        (directory / "curl.metrics.json").read_text()
    )
    assert metrics.size_download == 18
    assert metrics.time_total >= 0
    command = TypeAdapter(list[str]).validate_json(
        (directory / "curl.command.json").read_text()
    )
    assert command[command.index("--max-time") + 1] == "20"


def test_record_chain_preserves_evidence_after_assertion_failure(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    working = tmp_path / "working"
    working.mkdir()
    _ = (working / "curl.trace").write_text("partial transfer")
    config = create_echo_config(get_unique_port(), str(working))
    script = """
import sys
from pathlib import Path
from tests.fixtures.chain_diagnostics import record_chain
with record_chain(
    {'entry': Path(sys.argv[1])}, {'case': 'failure'},
    artifact_root=Path(sys.argv[2]),
) as capture:
    process = capture.start_proxy('entry', sys.argv[3])
    assert False, 'original failure must survive'
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(working), str(root), config],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert "original failure must survive" in result.stderr
    directories = list(root.iterdir())
    assert len(directories) == 1
    assert (directories[0] / "entry/curl.trace").read_text() == "partial transfer"
    assert str(directories[0]) in result.stderr
    assert "AssertionError" in (directories[0] / "manifest.json").read_text()
    manifest = ProcessEvidence.model_validate_json(
        (directories[0] / "manifest.json").read_text()
    )
    assert manifest.processes and manifest.failure
    assert all(not psutil.pid_exists(pid) for pid in manifest.processes.values())
    assert all(code is not None for code in manifest.exit_codes.values())


def test_record_chain_keeps_curl_failure_and_partial_body(tmp_path: Path) -> None:
    working = tmp_path / "working"
    working.mkdir()
    port = get_unique_port()
    release = threading.Event()

    def partial_response(connection: socket.socket) -> None:
        with connection:
            _ = read_http_request(connection)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
            _ = release.wait(2)

    with managed_target_servers() as start:
        _ = start(port, partial_response)
        try:
            with record_chain(
                {"entry": working},
                {"case": "curl-timeout"},
                artifact_root=tmp_path / "artifacts",
            ) as capture:
                directory = capture.directory
                result = capture.run_curl(
                    [
                        "curl",
                        "--silent",
                        "--show-error",
                        "--max-time",
                        "0.2",
                        "--noproxy",
                        "*",
                        "--trace-ascii",
                        str(working / "curl.trace"),
                        "--output",
                        str(working / "curl.body"),
                        "--write-out",
                        "%{http_code} %{http_connect}",
                        f"http://127.0.0.1:{port}/",
                    ]
                )
                assert result.returncode == 28
                assert result.stdout == "200 000"
                assert "timed out" in result.stderr
        finally:
            release.set()
    assert (directory / "curl.stderr").read_text() == result.stderr
    assert (directory / "entry/curl.body").read_bytes() == b"partial"
    assert "Content-Length: 100" in (directory / "entry/curl.trace").read_text()
    metrics = CurlMetrics.model_validate_json(
        (directory / "curl.metrics.json").read_text()
    )
    assert metrics.size_download == 7


def test_record_chain_preserves_curl_errors_before_metrics_are_available(
    tmp_path: Path,
) -> None:
    with record_chain(
        {}, {"case": "invalid-curl-option"}, artifact_root=tmp_path
    ) as capture:
        directory = capture.directory
        result = capture.run_curl(
            [
                "curl",
                "--neoproxy-invalid-option",
                "--write-out",
                "%{http_code} %{http_connect}",
                "http://127.0.0.1/",
            ]
        )
        assert result.returncode == 2
        assert result.stdout == ""
        assert "--neoproxy-invalid-option" in result.stderr
    assert (directory / "curl.stderr").read_text() == result.stderr
    assert (directory / "curl.metrics.error").read_text()
