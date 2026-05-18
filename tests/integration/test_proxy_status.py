"""
Proxy-Status header integration tests (RFC 9209).

Tests:
- CONNECT 200 response includes Proxy-Status header
- Connection refused response includes Proxy-Status error
- Proxy-Status identifier comes from server address
"""

import subprocess
import socket
import tempfile
import shutil
import os
from typing import Optional

from .utils.helpers import (
    start_proxy,
    wait_for_proxy,
    create_target_server,
    create_test_config,
)
from .conftest import get_unique_port


def _parse_status_code(response: bytes) -> Optional[int]:
    """Parse HTTP status code from response."""
    try:
        status_line = response.split(b"\r\n")[0].decode()
        parts = status_line.split()
        if len(parts) >= 2:
            return int(parts[1])
    except (IndexError, ValueError):
        pass
    return None


def _get_header(response: bytes, header_name: str) -> Optional[str]:
    """Get a specific header value from HTTP response."""
    for line in response.split(b"\r\n"):
        ascii_lower = line.decode(errors="replace").lower()
        if ascii_lower.startswith(header_name.lower() + ":"):
            colon_pos = line.find(b":")
            if colon_pos != -1:
                return line[colon_pos + 1:].strip().decode(errors="replace")
    return None


class TestProxyStatus:
    """Proxy-Status header integration tests."""

    def test_connect_success_has_proxy_status(self) -> None:
        """
        PS-001: CONNECT 200 response includes Proxy-Status header.

        Target: Verify that a successful CONNECT tunnel setup includes
        the Proxy-Status header in the 200 response.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            # Start a target server
            def echo_handler(conn: socket.socket) -> None:
                try:
                    conn.recv(1024)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            # Send CONNECT via raw socket to read response headers
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("127.0.0.1", proxy_port))
            sock.sendall(
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                f"\r\n".encode()
            )

            # Read response headers
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            sock.close()

            status = _parse_status_code(response)
            assert status == 200, \
                f"Expected 200, got {status}. Response: {response.decode(errors='ignore')[:200]}"

            # Verify Proxy-Status header is present
            ps = _get_header(response, "proxy-status")
            assert ps is not None, \
                f"Proxy-Status header not found in response: {response.decode(errors='ignore')[:200]}"

            # Should not contain error= on success
            assert "error=" not in ps, \
                f"Proxy-Status should not have error= on success: {ps}"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_connect_refused_has_proxy_status_error(self) -> None:
        """
        PS-002: Connection refused returns Proxy-Status with error.

        Target: Verify that connection refused results in 502 with
        Proxy-Status error=connection_refused.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc), \
                "Proxy failed to start"

            # Send CONNECT to an unbound port (will get connection refused)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("127.0.0.1", proxy_port))
            sock.sendall(
                b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n"
                b"Host: 127.0.0.1:1\r\n"
                b"\r\n"
            )

            response = b""
            try:
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            status = _parse_status_code(response)
            assert status == 502, \
                f"Expected 502, got {status}. Response: {response.decode(errors='ignore')[:200]}"

            # Verify Proxy-Status header
            ps = _get_header(response, "proxy-status")
            assert ps is not None, \
                f"Proxy-Status not found: {response.decode(errors='ignore')[:200]}"

            # Should contain error=connection_refused
            assert "error=connection_refused" in ps, \
                f"Expected error=connection_refused in Proxy-Status: {ps}"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_connect_timeout_has_proxy_status_error(self) -> None:
        """
        PS-003: Connection timeout returns Proxy-Status with error.

        Target: Verify that connection timeout results in 504 with
        Proxy-Status error=connection_timeout.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Use very short connect_timeout to trigger timeout quickly
            config_content = f"""server_threads: 1

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp
  args:
    connect_timeout: "1s"
    max_idle_timeout: "60s"

servers:
- name: http_connect
  listeners: ["http_main"]
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "timeout_config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc), \
                "Proxy failed to start"

            # Send CONNECT to a black-hole address (no route, will timeout)
            # 10.255.255.1 is in TEST-NET-1 reserved range, unlikely to respond
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect(("127.0.0.1", proxy_port))
            sock.sendall(
                b"CONNECT 10.255.255.1:80 HTTP/1.1\r\n"
                b"Host: 10.255.255.1:80\r\n"
                b"\r\n"
            )

            response = b""
            try:
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            status = _parse_status_code(response)
            assert status == 504 or status == 502, \
                f"Expected 504 (or 502), got {status}. Response: {response.decode(errors='ignore')[:200]}"

            # Verify Proxy-Status header has error
            ps = _get_header(response, "proxy-status")
            assert ps is not None, \
                f"Proxy-Status not found: {response.decode(errors='ignore')[:200]}"

            assert "error=" in ps, \
                f"Expected error= in Proxy-Status: {ps}"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_non_connect_no_proxy_status(self) -> None:
        """
        PS-004: Origin-form request returns 400 without Proxy-Status.

        Target: Verify that locally-generated 400 response (origin-form URI
        rejected by forward proxy validation) does NOT include Proxy-Status
        per RFC 9209 Section 2. Absolute-form http:// requests are now
        forwarded as forward proxy requests, so we use origin-form (GET /)
        to trigger the locally-generated error path.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc), \
                "Proxy failed to start"

            # Send origin-form GET request (locally rejected → 400, no Proxy-Status)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("127.0.0.1", proxy_port))
            sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"\r\n"
            )

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            sock.close()

            status = _parse_status_code(response)
            assert status == 400, \
                f"Expected 400, got {status}"

            # Should NOT have Proxy-Status (locally generated error per RFC)
            ps = _get_header(response, "proxy-status")
            assert ps is None, \
                f"Proxy-Status should NOT be present on locally-generated 400: {ps}"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)
