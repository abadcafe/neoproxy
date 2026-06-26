"""Integration tests for http_upstream using an HTTP upstream proxy."""

import os
import queue
import shutil
import socket
import ssl
import subprocess
import tempfile

from .conftest import get_unique_port
from .types import BytesProcess, TargetHandler
from .utils.certs import generate_test_certificates
from .utils.helpers import (
    create_target_server,
    start_proxy,
    terminate_process,
    wait_for_proxy,
)


def _read_headers(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _read_http_response(conn: socket.socket) -> bytes:
    data = _read_headers(conn)
    header_part, _, body = data.partition(b"\r\n\r\n")
    content_length = 0
    for line in header_part.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.lower() == b"content-length":
            content_length = int(value.strip())
    while len(body) < content_length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        body += chunk
    return data


def _write_http_upstream_config(entry_port: int, upstream_port: int, temp_dir: str) -> str:
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: http_chain
        addresses:
          - address: "127.0.0.1:{upstream_port}"
            http: {{}}

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{entry_port}"]

services:
  - name: chain
    kind: http_upstream.upstream
    args:
      upstream: http_chain

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
    config_path = os.path.join(temp_dir, "http_upstream_http_proxy.yaml")
    with open(config_path, "w", encoding="utf-8") as file:
        file.write(config_content)
    return config_path


def _write_https_upstream_config(entry_port: int, upstream_port: int, ca_path: str, temp_dir: str) -> str:
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: https_chain
        addresses:
          - address: "127.0.0.1:{upstream_port}"
            hostname: localhost
            https: {{}}

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{entry_port}"]

services:
  - name: chain
    kind: http_upstream.upstream
    args:
      upstream: https_chain

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
    config_path = os.path.join(temp_dir, "http_upstream_https_proxy.yaml")
    with open(config_path, "w", encoding="utf-8") as file:
        file.write(config_content)
    return config_path


def _tls_server_handler(cert_path: str, key_path: str, handler: TargetHandler) -> TargetHandler:
    def wrapped(conn: socket.socket) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        with context.wrap_socket(conn, server_side=True) as tls_conn:
            handler(tls_conn)

    return wrapped


def test_http_upstream_http_proxy_forward_request() -> None:
    temp_dir = tempfile.mkdtemp()
    entry_port = get_unique_port()
    upstream_port = get_unique_port()
    proxy_proc: BytesProcess | None = None
    upstream_socket: socket.socket | None = None
    request_lines: queue.Queue[str] = queue.Queue[str]()

    def upstream_handler(conn: socket.socket) -> None:
        try:
            data = _read_headers(conn)
            request_lines.put(data.split(b"\r\n", 1)[0].decode())
            body = b"via-http-upstream-forward"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Content-Type: text/plain\r\n\r\n"
                + body
            )
        finally:
            conn.close()

    try:
        _, upstream_socket = create_target_server(
            "127.0.0.1",
            upstream_port,
            upstream_handler,
        )
        config_path = _write_http_upstream_config(entry_port, upstream_port, temp_dir)
        proxy_proc = start_proxy(config_path)
        assert wait_for_proxy("127.0.0.1", entry_port, timeout=5.0, proc=proxy_proc)

        result: subprocess.CompletedProcess[str] = subprocess.run(
            [
                "curl",
                "-s",
                "-x",
                f"http://127.0.0.1:{entry_port}",
                "--max-time",
                "5",
                "http://example.test/resource",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout == "via-http-upstream-forward"
        assert request_lines.get(timeout=1).startswith("GET http://example.test/resource ")
    finally:
        if proxy_proc is not None:
            terminate_process(proxy_proc, timeout=5, force=True)
        if upstream_socket is not None:
            upstream_socket.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_http_upstream_https_proxy_forward_request() -> None:
    temp_dir = tempfile.mkdtemp()
    entry_port = get_unique_port()
    upstream_port = get_unique_port()
    cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
    proxy_proc: BytesProcess | None = None
    upstream_socket: socket.socket | None = None
    request_lines: queue.Queue[str] = queue.Queue[str]()

    def upstream_handler(conn: socket.socket) -> None:
        try:
            data = _read_headers(conn)
            request_lines.put(data.split(b"\r\n", 1)[0].decode())
            body = b"via-https-upstream-forward"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Content-Type: text/plain\r\n\r\n"
                + body
            )
        finally:
            conn.close()

    try:
        _, upstream_socket = create_target_server(
            "127.0.0.1",
            upstream_port,
            _tls_server_handler(cert_path, key_path, upstream_handler),
        )
        config_path = _write_https_upstream_config(entry_port, upstream_port, ca_path, temp_dir)
        proxy_proc = start_proxy(config_path)
        assert wait_for_proxy("127.0.0.1", entry_port, timeout=5.0, proc=proxy_proc)

        result: subprocess.CompletedProcess[str] = subprocess.run(
            [
                "curl",
                "-s",
                "-x",
                f"http://127.0.0.1:{entry_port}",
                "--max-time",
                "5",
                "http://example.test/secure-resource",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout == "via-https-upstream-forward"
        assert request_lines.get(timeout=1).startswith("GET http://example.test/secure-resource ")
    finally:
        if proxy_proc is not None:
            terminate_process(proxy_proc, timeout=5, force=True)
        if upstream_socket is not None:
            upstream_socket.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_http_upstream_http_proxy_connect_tunnel() -> None:
    temp_dir = tempfile.mkdtemp()
    entry_port = get_unique_port()
    upstream_port = get_unique_port()
    target_port = get_unique_port()
    proxy_proc: BytesProcess | None = None
    upstream_socket: socket.socket | None = None
    request_lines: queue.Queue[str] = queue.Queue[str]()

    def upstream_handler(conn: socket.socket) -> None:
        try:
            data = _read_headers(conn)
            request_lines.put(data.split(b"\r\n", 1)[0].decode())
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            tunneled = _read_headers(conn)
            request_lines.put(tunneled.split(b"\r\n", 1)[0].decode())
            body = b"via-http-upstream-connect"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Content-Type: text/plain\r\n\r\n"
                + body
            )
        finally:
            conn.close()

    try:
        _, upstream_socket = create_target_server(
            "127.0.0.1",
            upstream_port,
            upstream_handler,
        )
        config_path = _write_http_upstream_config(entry_port, upstream_port, temp_dir)
        proxy_proc = start_proxy(config_path)
        assert wait_for_proxy("127.0.0.1", entry_port, timeout=5.0, proc=proxy_proc)

        with socket.create_connection(("127.0.0.1", entry_port), timeout=5.0) as sock:
            sock.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode())
            connect_response = _read_headers(sock)
            assert b" 200 " in connect_response
            sock.sendall(b"GET / HTTP/1.1\r\nHost: tunnel-target\r\nConnection: close\r\n\r\n")
            tunneled_response = _read_http_response(sock)

        assert b"via-http-upstream-connect" in tunneled_response
        assert request_lines.get(timeout=1).startswith(f"CONNECT 127.0.0.1:{target_port} ")
        assert request_lines.get(timeout=1).startswith("GET / ")
    finally:
        if proxy_proc is not None:
            terminate_process(proxy_proc, timeout=5, force=True)
        if upstream_socket is not None:
            upstream_socket.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_http_upstream_https_proxy_connect_tunnel() -> None:
    temp_dir = tempfile.mkdtemp()
    entry_port = get_unique_port()
    upstream_port = get_unique_port()
    target_port = get_unique_port()
    cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
    proxy_proc: BytesProcess | None = None
    upstream_socket: socket.socket | None = None
    request_lines: queue.Queue[str] = queue.Queue[str]()

    def upstream_handler(conn: socket.socket) -> None:
        try:
            data = _read_headers(conn)
            request_lines.put(data.split(b"\r\n", 1)[0].decode())
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tunneled = _read_headers(conn)
            request_lines.put(tunneled.split(b"\r\n", 1)[0].decode())
            body = b"via-https-upstream-connect"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Content-Type: text/plain\r\n\r\n"
                + body
            )
        finally:
            conn.close()

    try:
        _, upstream_socket = create_target_server(
            "127.0.0.1",
            upstream_port,
            _tls_server_handler(cert_path, key_path, upstream_handler),
        )
        config_path = _write_https_upstream_config(entry_port, upstream_port, ca_path, temp_dir)
        proxy_proc = start_proxy(config_path)
        assert wait_for_proxy("127.0.0.1", entry_port, timeout=5.0, proc=proxy_proc)

        with socket.create_connection(("127.0.0.1", entry_port), timeout=5.0) as sock:
            sock.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode())
            connect_response = _read_headers(sock)
            assert b" 200 " in connect_response
            sock.sendall(b"GET / HTTP/1.1\r\nHost: tunnel-target\r\nConnection: close\r\n\r\n")
            tunneled_response = _read_http_response(sock)

        assert b"via-https-upstream-connect" in tunneled_response
        assert request_lines.get(timeout=1).startswith(f"CONNECT 127.0.0.1:{target_port} ")
        assert request_lines.get(timeout=1).startswith("GET / ")
    finally:
        if proxy_proc is not None:
            terminate_process(proxy_proc, timeout=5, force=True)
        if upstream_socket is not None:
            upstream_socket.close()
        shutil.rmtree(temp_dir, ignore_errors=True)
