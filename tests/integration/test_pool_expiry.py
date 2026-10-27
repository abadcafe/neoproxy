"""Process contract: pooled connections expire without another request."""

import http.client
import socket
import ssl
import threading
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
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
        relay["addresses"] = [
            {"address": f"127.0.0.1:{port}", "address_protocol": "http"}
        ]
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


@pytest.mark.parametrize("encrypted", [False, True])
def test_proxy_pool_reuses_one_connection_across_origin_authorities(
    tmp_path: Path, target_server: TargetServerFactory, encrypted: bool
) -> None:
    port = get_unique_port()
    connections: list[socket.socket] = []
    request_lines: list[bytes] = []
    lock = threading.Lock()
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)

    def upstream(raw: socket.socket) -> None:
        with lock:
            connections.append(raw)
        with raw:
            conn = tls.wrap_socket(raw, server_side=True) if encrypted else raw
            with conn:
                conn.settimeout(3)
                while True:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        data = conn.recv(4096)
                        if not data:
                            return
                        request += data
                    with lock:
                        request_lines.append(request.split(b"\r\n", 1)[0])
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    _ = target_server(port, upstream)
    protocol = "https" if encrypted else "http"
    config: ConfigDict = {
        "server_threads": 1,
        "plugins": {
            "http_upstream": {
                "certificates": {"server_ca_path": ca},
                "upstreams": [
                    {
                        "name": "relay",
                        "addresses": [
                            {
                                "address": f"127.0.0.1:{port}",
                                "hostname": "localhost",
                                "address_protocol": protocol,
                            }
                        ],
                    }
                ],
            }
        },
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
        client = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=3)
        try:
            targets = [
                "http://first.example/",
                "https://second.example:8443/",
                "https://third.example/",
            ]
            for target in targets:
                client.request("GET", target)
                response = client.getresponse()
                assert response.status == 200
                assert response.read() == b"OK"
            with lock:
                assert request_lines == [
                    f"GET {target} HTTP/1.1".encode() for target in targets
                ]
                assert len(connections) == 1, (
                    "pool was keyed by origin instead of proxy transport"
                )
        finally:
            client.close()
