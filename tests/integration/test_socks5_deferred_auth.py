"""Wire contracts for SOCKS5 credentials evaluated by the HTTP service chain."""

import socket
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel

from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.socks5_client import (
    socks5_connect_ipv4,
    socks5_handshake_no_auth,
    socks5_handshake_password,
)
from tests.fixtures.socks5_protocol import AuthMethod, AuthStatus, ReplyCode
from tests.fixtures.socks5_result import AuthReply, CommandReply, MethodReply

type Credentials = Literal["valid", "wrong", "unknown", "missing", "colon"]


class AccessEntry(BaseModel):
    method: str
    target: str
    status: int


def _receive_exact(client: socket.socket, size: int) -> bytes:
    received = b""
    while len(received) < size:
        chunk = client.recv(size - len(received))
        assert chunk, "connection closed before the expected payload"
        received += chunk
    return received


@pytest.mark.parametrize(
    "credentials", ["valid", "wrong", "unknown", "missing", "colon"]
)
def test_socks5_authentication_result_is_reported_by_connect_and_access_log(
    tmp_path: Path, credentials: Credentials
) -> None:
    proxy_port = get_unique_port()
    target_port = get_unique_port()
    config = tmp_path / "proxy.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  auth: {{}}
  http_upstream:
    upstreams:
    - name: direct
  access_log:
    writers:
    - path_prefix: logs/access
      rotate_daily: false
      format: json
listeners:
- name: main
  kind: socks5
  addresses: ["127.0.0.1:{proxy_port}"]
services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct
  layers:
  - kind: access_log.file
    args:
      writer: logs/access
  - kind: auth.basic_auth
    args:
      users:
      - username: user
        password: correct
      - username: "user:with:colon"
        password: "pass:word"
servers:
- name: main
  service: direct
  listeners: [main]
""")
    authorized = credentials in ("valid", "colon")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
        target.bind(("127.0.0.1", target_port))
        target.listen(1)
        target.settimeout(2)
        process = start_proxy(str(config))
        try:
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=3, proc=process)
            with socket.create_connection(
                ("127.0.0.1", proxy_port), timeout=2
            ) as client:
                if credentials == "missing":
                    assert socks5_handshake_no_auth(client) == MethodReply(
                        AuthMethod.NONE
                    )
                else:
                    username = "unknown" if credentials == "unknown" else "user"
                    password = "wrong" if credentials == "wrong" else "correct"
                    if credentials == "colon":
                        username, password = "user:with:colon", "pass:word"
                    status = socks5_handshake_password(client, username, password)
                    assert isinstance(status, AuthReply)
                    assert status.status is AuthStatus.SUCCESS, (
                        "Subnegotiation must finish before the converter receives "
                        + "the target and asks the HTTP service to authenticate"
                    )
                reply = socks5_connect_ipv4(client, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert (reply.code is ReplyCode.SUCCESS) == authorized
                expected = (
                    ReplyCode.SUCCESS
                    if authorized
                    else ReplyCode.CONNECTION_NOT_ALLOWED
                )
                assert reply.code is expected
                if authorized:
                    origin = target.accept()[0]
                    with origin:
                        origin.settimeout(2)
                        client.sendall(b"upload")
                        assert _receive_exact(origin, 6) == b"upload"
                        origin.sendall(b"response")
                        assert _receive_exact(client, 8) == b"response"
                else:
                    assert client.recv(1) == b"", "rejected CONNECT remained open"
        finally:
            terminate_process(process)
        assert process.returncode == 0
        target.setblocking(False)
        try:
            unexpected = target.accept()[0]
        except BlockingIOError:
            pass
        else:
            unexpected.close()
            pytest.fail("unauthorized or duplicate target connection")
    entries = [
        AccessEntry.model_validate_json(line)
        for line in (tmp_path / "logs" / "access").read_text().splitlines()
    ]
    assert len(entries) == 1
    assert entries[0].method == "CONNECT"
    assert entries[0].target == f"127.0.0.1:{target_port}"
    assert entries[0].status == (200 if authorized else 407)
