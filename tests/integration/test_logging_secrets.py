"""Verify logs preserve configuration details and mask password values."""

import base64
import os
import socket
import subprocess
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import terminate_process

CLIENT_USER = "np-live-private-client-user"
CLIENT_PASSWORD = "np-live-private-client-password"
UPSTREAM_USER = "np-live-private-upstream-user"
UPSTREAM_PASSWORD = "np-live-private-upstream-password"


def _configuration(directory: Path, port: int, listener_kind: str = "http") -> Path:
    path = directory / "proxy.yaml"
    _ = path.write_text(f"""server_threads: 2
plugins:
  echo: {{}}
  auth: {{}}
  upstream:
    user:
      username: {UPSTREAM_USER}
      password: {UPSTREAM_PASSWORD}
    upstreams:
    - name: unused-relay
      addresses:
      - address: 127.0.0.1:9
        address_protocol: http
listeners:
- name: main
  kind: {listener_kind}
  addresses: ["127.0.0.1:{port}"]
services:
- name: echo
  kind: echo.echo
  layers:
  - kind: auth.basic_auth
    args:
      users:
      - username: {CLIENT_USER}
        password: {CLIENT_PASSWORD}
servers:
- name: main
  service: echo
  listeners: [main]
""")
    return path


def _credentials() -> str:
    return base64.b64encode(f"{CLIENT_USER}:{CLIENT_PASSWORD}".encode()).decode()


def _request(port: int, authorization: str | None) -> bytes:
    headers = ""
    if authorization is not None:
        headers = f"Proxy-Authorization: Basic {authorization}\r\n"
    request = (
        "GET / HTTP/1.1\r\nHost: proxy.test\r\n" + headers + "Connection: close\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.sendall(request.encode())
        response = b""
        while chunk := client.recv(4096):
            response += chunk
        return response


def _assert_no_passwords(output: bytes) -> None:
    upstream_encoded = base64.b64encode(
        f"{UPSTREAM_USER}:{UPSTREAM_PASSWORD}".encode()
    ).decode()
    for value in (
        CLIENT_PASSWORD,
        UPSTREAM_PASSWORD,
        _credentials(),
        upstream_encoded,
    ):
        assert value.encode() not in output, "logs exposed configured passwords"


@pytest.mark.parametrize("log_filter", ["info", "neoproxy=trace"])
def test_startup_logs_mask_passwords_preserve_fields_and_authentication_works(
    tmp_path: Path, log_filter: Literal["info", "neoproxy=trace"]
) -> None:
    port = get_unique_port()
    config = _configuration(tmp_path, port)
    process = ProxyProcess(
        [NEOPROXY_BINARY, "--config", str(config)],
        cwd=tmp_path,
        env=dict(os.environ, NEOPROXY_LOG=log_filter),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait_ready(timeout=3)
        assert _request(port, None).startswith(b"HTTP/1.1 407 ")
        assert _request(port, _credentials()).startswith(b"HTTP/1.1 200 ")
    finally:
        terminate_process(process)
    assert process.returncode == 0
    stdout, stderr = process.communicate(timeout=1)
    files = tuple((tmp_path / "logs").glob("neoproxy.log*"))
    assert files, "diagnostic log was not created"
    diagnostics = b"".join(path.read_bytes() for path in files)
    assert b"server starting with 2 workers" in diagnostics
    assert b"shutdown complete" in diagnostics
    for value in (CLIENT_USER, UPSTREAM_USER, f"127.0.0.1:{port}", "unused-relay"):
        assert value.encode() in diagnostics, "logs omitted a non-secret config value"
    assert diagnostics.count(b'"*"') == 2
    assert b'"password"' in diagnostics
    _assert_no_passwords(stdout + stderr + diagnostics)


def test_invalid_configuration_diagnostics_do_not_dump_credentials(
    tmp_path: Path,
) -> None:
    config = _configuration(tmp_path, get_unique_port(), listener_kind="unknown")
    result = subprocess.run(
        [NEOPROXY_BINARY, "--config", str(config)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert result.returncode == 1
    assert b"unknown" in result.stdout + result.stderr
    _assert_no_passwords(result.stdout + result.stderr)
