"""Replay eligibility through two independently observed upstream peers."""

import socket
from pathlib import Path

import pytest

from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http_policy_scenario import configuration, exchange, read_request
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import TargetServerFactory


@pytest.mark.parametrize(
    "method,enabled,consumed,pre_send,expected",
    [
        ("POST", False, False, False, 502),
        ("POST", True, False, False, 200),
        ("GET", False, False, False, 200),
        ("PUT", True, True, False, 502),
        ("POST", True, True, False, 502),
        ("POST", False, False, True, 200),
        ("POST", False, True, True, 200),
    ],
)
def test_retry_obeys_send_boundary_and_body_replayability(
    tmp_path: Path,
    target_server: TargetServerFactory,
    method: str,
    enabled: bool,
    consumed: bool,
    pre_send: bool,
    expected: int,
) -> None:
    bad, good = get_unique_port(), get_unique_port()
    received: list[bytes] = []

    def first(conn: socket.socket) -> None:
        with conn:
            data = read_request(conn)
            if consumed:
                body = data.split(b"\r\n\r\n", 1)[1]
                while len(body) < 4:
                    chunk = conn.recv(4096)
                    assert chunk
                    body += chunk

    def second(conn: socket.socket) -> None:
        with conn:
            request = read_request(conn)
            if consumed:
                body = request.split(b"\r\n\r\n", 1)[1]
                while len(body) < 4:
                    chunk = conn.recv(4096)
                    assert chunk
                    body += chunk
                assert body == b"body"
            received.append(request)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    if not pre_send:
        _ = target_server(bad, first)
    _ = target_server(good, second)
    config = configuration({}, {})
    plugin: ConfigDict = {
        "upstream_non_idempotent_retry": enabled,
        "upstreams": [
            {
                "name": "main",
                "addresses": [
                    {"address": f"127.0.0.1:{bad}", "address_protocol": "http"},
                    {"address": f"127.0.0.1:{good}", "address_protocol": "http"},
                ],
            }
        ],
    }
    config["plugins"] = {"upstream": plugin}
    with running_proxy(tmp_path, config) as proxy:
        payload = b"body" if consumed else b""
        result = exchange(
            proxy.port,
            (
                f"{method} http://target.test/ HTTP/1.1\r\n"
                "Host: target.test\r\n"
                "Connection: close\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "\r\n"
            ).encode()
            + payload,
        )
        assert int(result.split(b" ")[1]) == expected
        assert len(received) == (1 if expected == 200 else 0)
