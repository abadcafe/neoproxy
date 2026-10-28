"""Exchange inactivity contracts through public proxy sockets."""

import socket
import threading
import time
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.forward_scenario import ForwardNode, write_forward_node
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.tcp_peer import TargetServerFactory

type Route = Literal["direct", "http", "https", "http3"]


@contextmanager
def proxy_route(directory: Path, protocol: Route) -> Generator[int]:
    cert, key, ca, _ = generate_test_certificates(
        str(directory), san_entries=["127.0.0.1", "proxy.test"]
    )
    entry = get_unique_port()
    with ExitStack() as stack:
        relay: int | None = None
        if protocol != "direct":
            relay = get_unique_port()
            config = write_forward_node(
                directory / "relay",
                ForwardNode(port=relay, listener=protocol, certificate=cert, key=key),
            )
            process = start_proxy(config)
            _ = stack.callback(terminate_process, process, timeout=5, force=True)
            assert process.wait_ready()
        config = write_forward_node(
            directory / "entry",
            ForwardNode(
                port=entry,
                ca=ca,
                certificate=cert,
                key=key,
                upstream_port=relay,
                upstream_kind="http" if protocol == "direct" else protocol,
                read_timeout="300ms",
                send_timeout="300ms",
            ),
        )
        process = start_proxy(config)
        _ = stack.callback(terminate_process, process, timeout=5, force=True)
        assert process.wait_ready()
        yield entry


def read_headers(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        assert chunk
        data += chunk
    return data


@pytest.mark.parametrize("protocol", ["direct", "http", "https", "http3"])
def test_long_upload_and_response_keep_making_progress(
    tmp_path: Path, target_server: TargetServerFactory, protocol: Route
) -> None:
    target = get_unique_port()
    received = threading.Event()

    def origin(conn: socket.socket) -> None:
        with conn:
            data = read_headers(conn).split(b"\r\n\r\n", 1)[1]
            while len(data) < 5:
                data += conn.recv(4096)
            received.set()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
            for _ in range(5):
                conn.sendall(b"x")
                time.sleep(0.1)

    _ = target_server(target, origin)
    with proxy_route(tmp_path, protocol) as port:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
            conn.sendall(
                (
                    f"POST http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\nContent-Length: 5\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            # A downstream pause exceeds both upstream deadlines. There
            # is nothing to write yet and the response is not due yet.
            time.sleep(0.5)
            for _ in range(5):
                conn.sendall(b"y")
                time.sleep(0.1)
            data = read_headers(conn)
            assert b"200" in data.split(b"\r\n", 1)[0]
            body = data.split(b"\r\n\r\n", 1)[1]
            while len(body) < 5:
                chunk = conn.recv(4096)
                assert chunk
                body += chunk
            assert body == b"xxxxx"
            assert received.is_set()


@pytest.mark.parametrize("protocol", ["direct", "http", "https", "http3"])
def test_response_header_stall_times_out(
    tmp_path: Path, target_server: TargetServerFactory, protocol: Route
) -> None:
    target = get_unique_port()
    release = threading.Event()

    def origin(conn: socket.socket) -> None:
        with conn:
            _ = read_headers(conn)
            _ = release.wait(3)

    _ = target_server(target, origin)
    try:
        with proxy_route(tmp_path, protocol) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                conn.sendall(
                    (
                        f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                        "Host: 127.0.0.1\r\n\r\n"
                    ).encode()
                )
                assert b"504" in read_headers(conn).split(b"\r\n", 1)[0]
    finally:
        release.set()


@pytest.mark.parametrize("protocol", ["direct", "http", "https", "http3"])
def test_response_body_stall_terminates_incomplete_response(
    tmp_path: Path, target_server: TargetServerFactory, protocol: Route
) -> None:
    target = get_unique_port()
    release = threading.Event()

    def origin(conn: socket.socket) -> None:
        with conn:
            _ = read_headers(conn)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx")
            _ = release.wait(3)

    _ = target_server(target, origin)
    try:
        with proxy_route(tmp_path, protocol) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                conn.sendall(
                    (
                        f"GET http://127.0.0.1:{target}/ HTTP/1.1\r\n"
                        "Host: 127.0.0.1\r\n\r\n"
                    ).encode()
                )
                data = read_headers(conn)
                assert b"200" in data.split(b"\r\n", 1)[0]
                body = data.split(b"\r\n\r\n", 1)[1]
                try:
                    while chunk := conn.recv(4096):
                        body += chunk
                except ConnectionResetError:
                    pass  # An aborted response may end with FIN or RST.
                assert body == b"x"
    finally:
        release.set()


@pytest.mark.parametrize("protocol", ["direct", "http", "https", "http3"])
def test_blocked_upload_times_out(
    tmp_path: Path, target_server: TargetServerFactory, protocol: Route
) -> None:
    import subprocess

    from tests.fixtures.curl import get_curl_env_without_no_proxy

    target = get_unique_port()
    release = threading.Event()

    def origin(conn: socket.socket) -> None:
        with conn:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            _ = read_headers(conn)
            _ = release.wait(10)

    _ = target_server(target, origin)
    payload = tmp_path / "upload.bin"
    _ = payload.write_bytes(b"x" * (32 * 1024 * 1024))
    try:
        with proxy_route(tmp_path, protocol) as port:
            result = subprocess.run(
                [
                    "curl",
                    "-sS",
                    "--proxy",
                    f"http://127.0.0.1:{port}",
                    "--max-time",
                    "6",
                    "-H",
                    "Expect:",
                    "--data-binary",
                    f"@{payload}",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    f"http://127.0.0.1:{target}/",
                ],
                capture_output=True,
                text=True,
                timeout=8,
                env=get_curl_env_without_no_proxy(),
            )
            assert result.returncode == 0, result.stderr
            assert result.stdout == "504", result.stdout
    finally:
        release.set()
