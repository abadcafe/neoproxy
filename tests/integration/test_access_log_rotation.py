"""Verify local calendar dates and restart-safe access log archives."""

import datetime
import os
import socket
import subprocess
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import terminate_process


def _run_requests(config: Path, port: int, timezone: str, indices: range) -> None:
    process = ProxyProcess(
        [NEOPROXY_BINARY, "--config", str(config)],
        cwd=config.parent,
        env=dict(os.environ, TZ=timezone),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait_ready(timeout=3)
        for index in indices:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(
                    (
                        f"GET /item-{index} HTTP/1.1\r\n"
                        + "Host: proxy.test\r\nConnection: close\r\n\r\n"
                    ).encode()
                )
                assert client.recv(4096).startswith(b"HTTP/1.1 200 ")
    finally:
        terminate_process(process)
    assert process.returncode == 0


def _config(directory: Path, port: int, writer_settings: str) -> Path:
    config = directory / "proxy.yaml"
    _ = config.write_text(f"""server_threads: 2
plugins:
  echo: {{}}
  access_log:
    writers:
    - path_prefix: logs/access
      buffer_capacity: 1B
      flush_interval: 10ms
{writer_settings}
listeners:
- name: main
  kind: http
  addresses: ["127.0.0.1:{port}"]
services:
- name: echo
  kind: echo.echo
  layers:
  - kind: access_log.file
    args:
      writer: logs/access
servers:
- name: main
  service: echo
  listeners: [main]
""")
    return config


@pytest.mark.parametrize("timezone", ["Pacific/Kiritimati", "Etc/GMT+12"])
def test_access_log_filename_uses_process_local_date(
    tmp_path: Path, timezone: str
) -> None:
    port = get_unique_port()
    config = _config(tmp_path, port, "      rotate_daily: true")
    local_timezone = ZoneInfo(timezone)
    before = datetime.datetime.now(local_timezone).date()
    _run_requests(config, port, timezone, range(1))
    after = datetime.datetime.now(local_timezone).date()
    names = {path.name for path in (tmp_path / "logs").glob("access*")}
    assert len(names) == 1, names
    assert names <= {f"access.{before}", f"access.{after}"}, names


def test_access_log_size_archives_continue_after_process_restart(
    tmp_path: Path,
) -> None:
    port = get_unique_port()
    config = _config(
        tmp_path, port, "      rotate_daily: false\n      max_file_size: 1B"
    )
    _run_requests(config, port, "Pacific/Kiritimati", range(3))
    original = {
        index: (tmp_path / "logs" / f"access.{index}").read_bytes() for index in (1, 2)
    }
    _run_requests(config, port, "Pacific/Kiritimati", range(3, 6))
    logs = tmp_path / "logs"
    assert {path.name for path in logs.glob("access*")} == {
        "access",
        *(f"access.{index}" for index in range(1, 6)),
    }
    for index, content in original.items():
        assert (logs / f"access.{index}").read_bytes() == content
    content = "".join(path.read_text() for path in logs.glob("access*"))
    assert len(content.splitlines()) == 6
    for index in range(6):
        assert content.count(f"/item-{index} ") == 1, content
