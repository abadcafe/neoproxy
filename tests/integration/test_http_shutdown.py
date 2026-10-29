"""Process tests for HTTP connection draining and CONNECT ownership transfer."""

import http.client
import signal
import socket
import ssl
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.http_configuration import create_test_config
from tests.fixtures.ports import get_unique_port, wait_for_port_released
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.tcp_peer import TargetServerFactory

type ListenerKind = Literal["http", "https"]


@contextmanager
def running_proxy(
    directory: Path, listener_kind: ListenerKind
) -> Generator[tuple[BytesProcess, http.client.HTTPConnection]]:
    port = get_unique_port()
    config = Path(create_test_config(port, str(directory)))
    context: ssl.SSLContext | None = None
    if listener_kind == "https":
        cert, key, _, _ = generate_test_certificates(str(directory))
        content = config.read_text().replace("  kind: http\n", "  kind: https\n")
        content += (
            f"  certificates:\n  - cert_path: {cert}\n" + f"    key_path: {key}\n"
        )
        _ = config.write_text(content)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    process = start_proxy(str(config))
    try:
        assert process.wait_ready()
        connection.connect()
        if context is not None:
            stream = connection.sock
            assert isinstance(stream, socket.socket)
            connection.sock = context.wrap_socket(stream, server_hostname="localhost")
        yield process, connection
    finally:
        connection.close()
        terminate_process(process, timeout=1, force=True)


def read_request(connection: socket.socket) -> None:
    with connection.makefile("rb") as reader:
        _ = reader.readline()
        headers = http.client.parse_headers(reader)
        _ = reader.read(int(headers.get("Content-Length", "0")))


@pytest.mark.parametrize("listener_kind", ["http", "https"])
def test_shutdown_closes_idle_keepalive_connection(
    tmp_path: Path, listener_kind: ListenerKind, target_server: TargetServerFactory
) -> None:
    port = get_unique_port()
    release = threading.Event()

    def target(connection: socket.socket) -> None:
        with connection:
            read_request(connection)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            _ = release.wait(6)

    _ = target_server(port, target)
    try:
        with running_proxy(tmp_path, listener_kind) as (process, connection):
            connection.request("GET", f"http://127.0.0.1:{port}/")
            with connection.getresponse() as response:
                assert response.status == 200
                assert response.read() == b"OK"
            stream = connection.sock
            assert isinstance(stream, socket.socket)
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            assert stream.recv(1) == b""
            assert process.wait(timeout=2) == 0
            assert time.monotonic() - started < 2
    finally:
        release.set()


@pytest.mark.parametrize("listener_kind", ["http", "https"])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_shutdown_finishes_response_body_before_closing(
    tmp_path: Path,
    listener_kind: ListenerKind,
    method: Literal["GET", "POST"],
    target_server: TargetServerFactory,
) -> None:
    port = get_unique_port()
    release = threading.Event()

    def target(connection: socket.socket) -> None:
        with connection:
            read_request(connection)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
            if release.wait(6):
                connection.sendall(b"last!")

    _ = target_server(port, target)
    try:
        with running_proxy(tmp_path, listener_kind) as (process, connection):
            connection.request(method, f"http://127.0.0.1:{port}/", body=b"upload")
            with connection.getresponse() as response:
                assert response.status == 200
                assert response.read(5) == b"first"
                process.send_signal(signal.SIGTERM)
                # Confirm shutdown has stopped accepting before finishing the body.
                assert wait_for_port_released("127.0.0.1", connection.port, timeout=1)
                assert process.poll() is None
                release.set()
                assert response.read() == b"last!"
            stream = connection.sock
            assert isinstance(stream, socket.socket)
            assert stream.recv(1) == b""
            assert process.wait(timeout=2) == 0
    finally:
        release.set()


@pytest.mark.parametrize("listener_kind", ["http", "https"])
def test_shutdown_finishes_post_upload_before_closing(
    tmp_path: Path, listener_kind: ListenerKind, target_server: TargetServerFactory
) -> None:
    port = get_unique_port()
    uploading = threading.Event()

    def target(connection: socket.socket) -> None:
        with connection, connection.makefile("rb") as reader:
            _ = reader.readline()
            _ = http.client.parse_headers(reader)
            first = reader.read(5)
            uploading.set()
            last = reader.read(5)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n" + first + last
            )

    _ = target_server(port, target)
    with running_proxy(tmp_path, listener_kind) as (process, connection):
        connection.putrequest("POST", f"http://127.0.0.1:{port}/")
        connection.putheader("Content-Length", "10")
        connection.endheaders()
        # HTTPConnection.send uses socket.sendall internally. Keep its
        # streaming API so shutdown still happens between upload chunks.
        connection.send(b"first")
        assert uploading.wait(2)
        process.send_signal(signal.SIGTERM)
        assert wait_for_port_released("127.0.0.1", connection.port, timeout=1)
        assert process.poll() is None
        connection.send(b"last!")
        with connection.getresponse() as response:
            assert response.status == 200
            assert response.read() == b"firstlast!"
        assert process.wait(timeout=2) == 0


@pytest.mark.parametrize("listener_kind", ["http", "https"])
def test_shutdown_cancels_stalled_response_at_listener_deadline(
    tmp_path: Path, listener_kind: ListenerKind, target_server: TargetServerFactory
) -> None:
    port = get_unique_port()
    release = threading.Event()

    def target(connection: socket.socket) -> None:
        with connection:
            read_request(connection)
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
            _ = release.wait(6)

    _ = target_server(port, target)
    try:
        with running_proxy(tmp_path, listener_kind) as (process, connection):
            connection.request("GET", f"http://127.0.0.1:{port}/")
            with connection.getresponse() as response:
                assert response.status == 200
                assert response.read(5) == b"first"
                stream = connection.sock
                assert isinstance(stream, socket.socket)
                stream.settimeout(6)
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                # Reading one byte observes EOF without hiding a truncated body.
                assert response.read(1) == b""
                assert process.wait(timeout=2) == 0
                assert 2.5 <= time.monotonic() - started < 6
                assert not release.is_set()
    finally:
        release.set()


@pytest.mark.parametrize("listener_kind", ["http", "https"])
def test_shutdown_closes_upgraded_connect_without_waiting_for_peer_eof(
    tmp_path: Path, listener_kind: ListenerKind, target_server: TargetServerFactory
) -> None:
    port = get_unique_port()
    closed = threading.Event()

    def target(connection: socket.socket) -> None:
        with connection:
            connection.sendall(connection.recv(1))
            while connection.recv(1024):
                pass
        closed.set()

    _ = target_server(port, target)
    with running_proxy(tmp_path, listener_kind) as (process, connection):
        stream = connection.sock
        assert isinstance(stream, socket.socket)
        # Send CONNECT over the listener transport, including TLS for HTTPS.
        # HTTPConnection.set_tunnel would establish a fresh plaintext socket.
        authority = f"127.0.0.1:{port}"
        request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        stream.sendall(request.encode())
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            byte = stream.recv(1)
            assert byte
            head += byte
        assert head.startswith(b"HTTP/1.1 200 ")
        stream.sendall(b"X")
        assert stream.recv(1) == b"X"
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        assert stream.recv(1) == b""
        assert closed.wait(1)
        assert process.wait(timeout=2) == 0
        assert time.monotonic() - started < 2


def test_shutdown_cancels_tls_handshake_without_waiting_for_handshake_timeout(
    tmp_path: Path,
) -> None:
    with running_proxy(tmp_path, "https") as (process, connection):
        with socket.create_connection(
            (connection.host, connection.port), timeout=2
        ) as raw:
            # A partial TLS record keeps the handshake pending.
            raw.sendall(b"\x16\x03")
            process.send_signal(signal.SIGTERM)
            try:
                data = raw.recv(1)
            except ConnectionResetError:
                # A cancelled, incomplete handshake can close with TCP RST.
                data = b""
            assert data == b""
            assert process.wait(timeout=2) == 0


def test_shutdown_cancels_upstream_connect_operation_and_its_driver(
    tmp_path: Path, target_server: TargetServerFactory
) -> None:
    upstream_port = get_unique_port()
    entry_port = get_unique_port()
    received = threading.Event()
    closed = threading.Event()

    def upstream(connection: socket.socket) -> None:
        with connection:
            connection.settimeout(8)
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                data = connection.recv(1)
                assert data
                head += data
            assert head.startswith(b"CONNECT ")
            received.set()
            assert connection.recv(1) == b""
            closed.set()

    _ = target_server(upstream_port, upstream)
    path = tmp_path / "pending-connect.yaml"
    _ = path.write_text(f"""server_threads: 1
plugins:
  upstream:
    upstreams:
    - name: relay
      addresses:
      - address: 127.0.0.1:{upstream_port}
        address_protocol: http
        upstream_read_timeout: 30s
listeners:
- name: main
  kind: http
  addresses: ["127.0.0.1:{entry_port}"]
services:
- name: relay
  kind: upstream.upstream
  upstream: relay
servers:
- name: main
  service: relay
  listeners: [main]
""")
    process = start_proxy(str(path))
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", entry_port), timeout=2) as client:
            client.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
            )
            assert received.wait(2)
            process.send_signal(signal.SIGTERM)
            # The listener's 3s request budget cancels the whole operation.
            # A detached driver would survive until plugin cleanup timed out.
            assert closed.wait(4.5)
            assert process.wait(timeout=2) == 0
    finally:
        terminate_process(process)
