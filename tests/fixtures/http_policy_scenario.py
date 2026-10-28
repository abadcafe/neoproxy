"""Configure and exchange raw HTTP policy scenarios through public sockets.
Public operations: configuration, exchange, read_request.
Tests: integration/test_http_header_limits.py and test_listener_io_timeout.py.
"""

import socket

from .configuration import ConfigDict


def configuration(listener: ConfigDict, pool: ConfigDict) -> ConfigDict:
    return {
        "server_threads": 1,
        "plugins": {
            "upstream": {
                "upstreams": [{"name": "main"}],
                "connection_pools": [{"name": "default", **pool}],
            }
        },
        "listeners": [{"name": "main", "kind": "http", **listener}],
        "services": [{"name": "main", "kind": "upstream.upstream", "upstream": "main"}],
        "servers": [{"name": "main", "listeners": ["main"], "service": "main"}],
    }


def exchange(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        result = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return result
            result += chunk


def read_request(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        assert chunk
        data += chunk
    return data
