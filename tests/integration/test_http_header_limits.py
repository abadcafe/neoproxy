"""Incoming header budgets through listener and upstream sockets."""

import socket
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http3_client import H3Client
from tests.fixtures.http_policy_scenario import configuration, exchange, read_request
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import TargetServerFactory


@pytest.mark.parametrize("size,expected", [(32_768, 200), (32_769, 431)])
def test_default_request_header_budget(
    tmp_path: Path, target_server: TargetServerFactory, size: int, expected: int
) -> None:
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            _ = read_request(conn)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    _ = target_server(target, origin)
    with running_proxy(tmp_path, configuration({}, {})) as proxy:
        prefix = (
            f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "X-Large: "
        ).encode()
        request = prefix + b"a" * (size - len(prefix) - 4) + b"\r\n\r\n"
        assert len(request) == size
        result = exchange(proxy.port, request)
        assert int(result.split(b" ")[1]) == expected


@pytest.mark.parametrize("count,expected", [(3, 200), (4, 431)])
def test_request_count_includes_repeated_fields(
    tmp_path: Path, target_server: TargetServerFactory, count: int, expected: int
) -> None:
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            _ = read_request(conn)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    _ = target_server(target, origin)
    with running_proxy(
        tmp_path, configuration({"max_request_headers": 5}, {})
    ) as proxy:
        result = exchange(
            proxy.port,
            (
                f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Connection: close\r\n"
            ).encode()
            + b"X-Repeated: a\r\n" * count
            + b"\r\n",
        )
        assert int(result.split(b" ")[1]) == expected


@pytest.mark.parametrize(
    "headers,pool,expected",
    [
        (b"X-Large: " + b"a" * 31_000 + b"\r\n", {}, 200),
        (b"X-Large: " + b"a" * 33_000 + b"\r\n", {}, 502),
        (b"Set-Cookie: a\r\n" * 3, {"max_response_headers": 3}, 502),
        (
            b"X-Large: " + b"a" * 2048 + b"\r\n",
            {"max_response_header_size": "1KiB"},
            502,
        ),
    ],
    ids=["below-default", "above-default", "repeated-count", "custom-size"],
)
def test_upstream_response_header_limits(
    tmp_path: Path,
    target_server: TargetServerFactory,
    headers: bytes,
    pool: ConfigDict,
    expected: int,
) -> None:
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            _ = read_request(conn)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n" + headers + b"Content-Length: 2\r\n\r\nOK"
            )

    _ = target_server(target, origin)
    with running_proxy(tmp_path, configuration({}, pool)) as proxy:
        result = exchange(
            proxy.port,
            (
                f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode(),
        )
        assert int(result.split(b" ")[1]) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("budget", ["count", "size"])
async def test_h3_header_limit_rejects_one_stream_and_preserves_connection(
    tmp_path: Path,
    budget: str,
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    config: ConfigDict = {
        "server_threads": 1,
        "plugins": {"echo": {}},
        "listeners": [
            {
                "name": "main",
                "kind": "http3",
                "max_request_headers": 2 if budget == "count" else 100,
                "max_request_header_size": "1KiB" if budget == "size" else "32KiB",
            }
        ],
        "services": [{"name": "main", "kind": "echo.echo"}],
        "servers": [
            {
                "name": "main",
                "listeners": ["main"],
                "service": "main",
                "certificates": [{"cert_path": cert, "key_path": key}],
            }
        ],
    }
    with running_proxy(tmp_path, config) as proxy:
        client = H3Client("127.0.0.1", proxy.port, ca_path=ca)
        assert await client.connect()
        try:
            response = await client.send_request(
                "GET",
                "/",
                [("x-test", "a")] * 3
                if budget == "count"
                else [("x-test", "a" * 2000)],
            )
            assert (
                response.status_code == 431
                if budget == "count"
                else response.status_code in (0, 431)
            )
            response = await client.send_request("GET", "/")
            assert response.status_code == 200
        finally:
            await client.close()
