"""Observe periodic access-log persistence while the proxy remains running."""

import socket
import time
from pathlib import Path

from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import start_proxy, terminate_process


def _wait_for_log(path: Path, marker: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and marker in path.read_text():
            return True
        time.sleep(0.002)
    return False


def _request(port: int, target: str) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        client.sendall(
            f"GET {target} HTTP/1.1\r\n".encode()
            + b"Host: proxy.test\r\nConnection: close\r\n\r\n"
        )
        response = b""
        while chunk := client.recv(4096):
            response += chunk
        assert response.startswith(b"HTTP/1.1 200 "), response


def test_access_log_periodic_flush_is_not_delayed_by_size_flush(tmp_path: Path) -> None:
    port = get_unique_port()
    config = tmp_path / "proxy.yaml"
    _ = config.write_text(f"""server_threads: 2
plugins:
  echo: {{}}
  access_log:
    writers:
    - path_prefix: logs/access
      rotate_daily: false
      buffer_capacity: 4KiB
      flush_interval: 1s
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
    process = start_proxy(str(config))
    log = tmp_path / "logs" / "access"
    try:
        assert wait_for_proxy("127.0.0.1", port, timeout=3, proc=process)
        _request(port, "/timer-anchor")
        assert _wait_for_log(log, "/timer-anchor", timeout=3)
        anchor = time.monotonic()
        time.sleep(0.6)
        _request(port, "/size-flush-" + "x" * 5000)
        assert _wait_for_log(log, "/size-flush-", timeout=0.2)
        assert time.monotonic() - anchor < 0.8, "missed test scheduling window"
        _request(port, "/pending-after-size-flush")
        # The proxy stays alive and receives no further requests, so
        # only its periodic timer can persist this small buffered entry.
        assert _wait_for_log(log, "/pending-after-size-flush", timeout=1.1)
        assert process.poll() is None
        _request(port, "/final-buffered")
    finally:
        terminate_process(process)
    assert process.returncode == 0
    content = log.read_text()
    assert len(content.splitlines()) == 4
    assert "/final-buffered" in content
