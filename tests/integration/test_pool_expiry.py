"""Process contract: pooled connections expire without another request."""

import http.client
import socket
import threading
from pathlib import Path

import pytest

from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import TargetServerFactory


@pytest.mark.parametrize("chained", [False, True])
def test_pool_idle_timeout_closes_unused_connection(
    tmp_path: Path, target_server: TargetServerFactory, chained: bool
) -> None:
    port = get_unique_port()
    expired = threading.Event()

    def upstream(conn: socket.socket) -> None:
        with conn:
            conn.settimeout(2)
            request = b""
            while b"\r\n\r\n" not in request:
                data = conn.recv(4096)
                if not data:
                    return
                request += data
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            try:
                if conn.recv(1) == b"":
                    expired.set()
            except TimeoutError:
                return

    _ = target_server(port, upstream)
    relay: ConfigDict = {"name": "relay", "pool": {"idle_timeout": "100ms"}}
    if chained:
        relay["addresses"] = [{"address": f"127.0.0.1:{port}", "http": {}}]
    config: ConfigDict = {
        "server_threads": 1,
        "plugins": {"http_upstream": {"upstreams": [relay]}},
        "listeners": [{"name": "main", "kind": "http"}],
        "services": [
            {
                "name": "relay",
                "kind": "http_upstream.upstream",
                "args": {"upstream": "relay"},
            }
        ],
        "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
    }
    with running_proxy(tmp_path, config) as proxy:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=2)
        try:
            conn.request("GET", f"http://127.0.0.1:{port}/")
            response = conn.getresponse()
            assert response.status == 200
            assert response.read() == b"ok"
            assert expired.wait(1), (
                "idle upstream socket was retained past its deadline"
            )
        finally:
            conn.close()
