"""
connect_tcp forward proxy integration tests.

Test target: Verify connect_tcp service handles non-CONNECT HTTP requests
as a forward proxy (GET/POST/etc. with absolute-form URIs).

Test nature: Black-box testing through external interface (HTTP)

Expected behavior:
- GET http://target/ -> forwarded to target, response returned
- POST http://target/ with body -> forwarded with body
- GET / HTTP/1.1 (origin-form) -> 400 Bad Request
- GET https://target/ -> 400 Bad Request (only http:// supported)
- GET http://unreachable/ -> 502 Bad Gateway
- Proxy-Status header present in responses
"""

import subprocess
import socket
import tempfile
import shutil
import threading
from typing import Optional, List, Tuple

from .utils.helpers import (
    start_proxy,
    wait_for_proxy,
    send_raw_request,
    create_target_server,
    create_test_config,
    terminate_process,
    curl_request_with_headers,
    get_curl_env_without_no_proxy,
)
from .conftest import get_unique_port


def parse_http_status(response: bytes) -> int:
    """Extract HTTP status code from raw response bytes."""
    try:
        first_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
        parts = first_line.split()
        return int(parts[1]) if len(parts) >= 2 else 0
    except Exception:
        return 0


def make_http_target_server(
    host: str,
    port: int,
    status: int = 200,
    body: bytes = b"hello",
    extra_headers: str = "",
) -> Tuple[threading.Thread, socket.socket]:
    """
    Start a minimal HTTP/1.1 server that returns a fixed response.

    Returns (thread, server_socket).
    """
    body_len = len(body)
    response = (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n"
        f"{extra_headers}"
        f"\r\n"
    ).encode() + body

    def handler(conn: socket.socket) -> None:
        try:
            # Drain the request
            buf = b""
            conn.settimeout(2.0)
            try:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                # Drain body if Content-Length present
                if b"content-length:" in buf.lower():
                    for line in buf.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            cl = int(line.split(b":", 1)[1].strip())
                            header_end = buf.index(b"\r\n\r\n") + 4
                            already = len(buf) - header_end
                            remaining = cl - already
                            while remaining > 0:
                                chunk = conn.recv(min(remaining, 4096))
                                if not chunk:
                                    break
                                remaining -= len(chunk)
                            break
            except socket.timeout:
                pass
            conn.sendall(response)
        except Exception:
            pass
        finally:
            conn.close()

    return create_target_server(host, port, handler)


class TestConnectTcpForwardProxy:
    """Integration tests for connect_tcp forward proxy (non-CONNECT requests)."""

    def test_origin_form_returns_400(self) -> None:
        """
        TC-FWD-001: origin-form URI returns 400.

        GET / HTTP/1.1 is not an absolute-form URI, so the forward proxy
        rejects it with 400 Bad Request.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            assert parse_http_status(response) == 400, \
                f"Expected 400 for origin-form GET, got: {response.decode(errors='ignore')}"
        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_https_scheme_returns_400(self) -> None:
        """
        TC-FWD-002: https:// scheme returns 400.

        The forward proxy only supports http:// URIs. https:// is rejected
        with 400 Bad Request.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            request = b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            assert parse_http_status(response) == 400, \
                f"Expected 400 for https:// scheme, got: {response.decode(errors='ignore')}"
        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_get_request_forwarded_successfully(self) -> None:
        """
        TC-FWD-003: GET http://target/ is forwarded and response returned.

        The proxy forwards the request to the target server and returns
        the target's response to the client.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            _, target_socket = make_http_target_server(
                "127.0.0.1", target_port, status=200, body=b"forward-ok"
            )

            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            status_code, resp_headers, body = curl_request_with_headers(
                url=f"http://127.0.0.1:{target_port}/",
                proxy_port=proxy_port,
                timeout=5,
            )

            assert status_code == 200, \
                f"Expected 200 from forwarded GET, got {status_code}"
            assert "forward-ok" in body, \
                f"Expected body 'forward-ok', got: {body!r}"
        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_post_request_with_body_forwarded(self) -> None:
        """
        TC-FWD-004: POST http://target/ with body is forwarded correctly.

        The proxy forwards the POST body to the target and returns the
        target's response.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None
        received_bodies: List[bytes] = []

        def capturing_handler(conn: socket.socket) -> None:
            try:
                buf = b""
                conn.settimeout(2.0)
                try:
                    while b"\r\n\r\n" not in buf:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    # Read body
                    body_bytes = b""
                    if b"content-length:" in buf.lower():
                        for line in buf.split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                cl = int(line.split(b":", 1)[1].strip())
                                header_end = buf.index(b"\r\n\r\n") + 4
                                body_bytes = buf[header_end:]
                                remaining = cl - len(body_bytes)
                                while remaining > 0:
                                    chunk = conn.recv(min(remaining, 4096))
                                    if not chunk:
                                        break
                                    body_bytes += chunk
                                    remaining -= len(chunk)
                                break
                except socket.timeout:
                    pass
                received_bodies.append(body_bytes)
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                    b"OK"
                )
                conn.sendall(resp)
            except Exception:
                pass
            finally:
                conn.close()

        try:
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, capturing_handler
            )

            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            post_body = b"key=value&foo=bar"
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-x", f"http://127.0.0.1:{proxy_port}",
                "-X", "POST",
                "-d", post_body.decode(),
                "--connect-timeout", "5",
                "--max-time", "5",
                f"http://127.0.0.1:{target_port}/submit",
            ]
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, env=env
            )
            status_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0

            assert status_code == 200, \
                f"Expected 200 from forwarded POST, got {status_code}"
            assert any(post_body in b for b in received_bodies), \
                f"Target did not receive POST body. Got: {received_bodies}"
        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_unreachable_target_returns_502(self) -> None:
        """
        TC-FWD-005: Unreachable target returns 502 Bad Gateway.

        When the forward proxy cannot connect to the target, it returns
        502 Bad Gateway.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Bind and immediately release a port so we know it's not listening
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            dead_port = listener.getsockname()[1]
            listener.close()

            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            request = (
                f"GET http://127.0.0.1:{dead_port}/ HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{dead_port}\r\n"
                f"\r\n"
            ).encode()
            response = send_raw_request("127.0.0.1", proxy_port, request, timeout=8.0)

            status = parse_http_status(response)
            assert status == 502, \
                f"Expected 502 for unreachable target, got {status}: " \
                f"{response.decode(errors='ignore')}"
        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_proxy_status_header_present(self) -> None:
        """
        TC-FWD-006: Proxy-Status header is present in forward proxy responses.

        The proxy appends a Proxy-Status entry (RFC 9209) to responses.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            _, target_socket = make_http_target_server(
                "127.0.0.1", target_port, status=200, body=b"ok"
            )

            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            status_code, resp_headers, _ = curl_request_with_headers(
                url=f"http://127.0.0.1:{target_port}/",
                proxy_port=proxy_port,
                timeout=5,
            )

            assert status_code == 200, \
                f"Expected 200, got {status_code}"
            assert "proxy-status" in resp_headers, \
                f"Expected Proxy-Status header, got headers: {resp_headers}"
        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_connect_method_still_works(self) -> None:
        """
        TC-FWD-007: CONNECT method still works alongside forward proxy.

        Adding forward proxy support must not break CONNECT tunnel behavior.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        def echo_handler(conn: socket.socket) -> None:
            try:
                data = conn.recv(1024)
                if data:
                    conn.sendall(b"ECHO:" + data)
            except Exception:
                pass
            finally:
                conn.close()

        try:
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                connect_req = (
                    f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{target_port}\r\n\r\n"
                ).encode()
                sock.sendall(connect_req)

                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    resp += chunk

                assert b"200" in resp, \
                    f"Expected 200 CONNECT response, got: {resp.decode(errors='ignore')}"

                sock.sendall(b"HELLO")
                echo = sock.recv(1024)
                assert echo == b"ECHO:HELLO", \
                    f"Expected echo, got: {echo!r}"
            finally:
                sock.close()
        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
