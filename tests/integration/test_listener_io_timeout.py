"""Listener timeouts measure blocked I/O without limiting streaming duration."""

import socket
import threading
import time
from pathlib import Path

import pytest

from tests.fixtures.http_policy_scenario import configuration, read_request
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import TargetServerFactory


@pytest.mark.parametrize("progress", [False, True])
def test_listener_body_read_timeout(
    tmp_path: Path, target_server: TargetServerFactory, progress: bool
) -> None:
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            data = read_request(conn).split(b"\r\n\r\n", 1)[1]
            while len(data) < 5:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    _ = target_server(target, origin)
    config = configuration({"body_read_timeout": "300ms", "write_timeout": "300ms"}, {})
    with running_proxy(tmp_path, config) as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=3) as conn:
            conn.sendall(
                (
                    f"POST http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Content-Length: 5\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode()
            )
            if progress:
                for _ in range(5):
                    conn.sendall(b"x")
                    time.sleep(0.1)
            response = read_request(conn)
            assert int(response.split(b" ")[1]) == (200 if progress else 408)


def test_listener_write_timeout_does_not_count_waiting_for_origin(
    tmp_path: Path, target_server: TargetServerFactory
) -> None:
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            _ = read_request(conn)
            time.sleep(0.6)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
            for _ in range(5):
                time.sleep(0.4)
                conn.sendall(b"x")

    _ = target_server(target, origin)
    with running_proxy(
        tmp_path, configuration({"write_timeout": "200ms"}, {})
    ) as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=4) as conn:
            conn.sendall(
                (
                    f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode()
            )
            response = read_request(conn)
            assert b" 200 " in response.split(b"\r\n")[0]
            body = response.split(b"\r\n\r\n", 1)[1]
            while len(body) < 5:
                chunk = conn.recv(4096)
                assert chunk
                body += chunk
            assert body == b"xxxxx"


def test_listener_blocked_write_closes_exchange(
    tmp_path: Path, target_server: TargetServerFactory
) -> None:
    target = get_unique_port()
    stopped = threading.Event()

    def origin(conn: socket.socket) -> None:
        with conn:
            _ = read_request(conn)
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n")
                while True:
                    conn.sendall(b"x" * 65536)
            except OSError:
                stopped.set()

    _ = target_server(target, origin)
    with running_proxy(
        tmp_path, configuration({"write_timeout": "200ms"}, {})
    ) as proxy:
        with socket.socket() as conn:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            conn.connect(("127.0.0.1", proxy.port))
            conn.sendall(
                (
                    f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "\r\n"
                ).encode()
            )
            assert stopped.wait(4), (
                "blocked client did not cancel the upstream response"
            )


def test_fragmented_trailers_reset_body_read_timeout(
    tmp_path: Path, target_server: TargetServerFactory
) -> None:
    target = get_unique_port()

    def origin(conn: socket.socket) -> None:
        with conn:
            data = read_request(conn).split(b"\r\n\r\n", 1)[1]
            while b"0\r\n" not in data or not data.endswith(b"\r\n\r\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

    _ = target_server(target, origin)
    with running_proxy(
        tmp_path, configuration({"body_read_timeout": "300ms"}, {})
    ) as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=3) as conn:
            conn.sendall(
                (
                    f"POST http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Trailer: X-Test\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "1\r\n"
                    "a\r\n"
                    "0\r\n"
                    "X-Test: "
                ).encode()
            )
            for _ in range(6):
                conn.sendall(b"a")
                time.sleep(0.1)
            conn.sendall(b"\r\n\r\n")
            assert b" 200 " in read_request(conn).split(b"\r\n")[0]


def test_partial_request_line_does_not_restart_first_header_deadline(
    tmp_path: Path,
) -> None:
    with running_proxy(
        tmp_path, configuration({"header_read_timeout": "600ms"}, {})
    ) as proxy:
        with socket.create_connection(("127.0.0.1", proxy.port), timeout=2) as conn:
            # Progress on a partial request line must not extend the deadline.
            conn.sendall(b"P")
            time.sleep(0.4)
            conn.sendall(b"O")
            conn.settimeout(0.4)
            response = conn.recv(4096)
            assert not response or b"408" in response.split(b"\r\n")[0]
