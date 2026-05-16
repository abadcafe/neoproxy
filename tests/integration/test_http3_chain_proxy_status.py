"""
Integration tests for http3_chain Proxy-Status header (RFC 9209).

Tests:
- H3C-PS-001: CONNECT success includes Proxy-Status with received-status=200
- H3C-PS-002: Upstream unreachable includes Proxy-Status error
- H3C-PS-003: Upstream returns error includes Proxy-Status with received-status
"""

import socket
import subprocess
import tempfile
from typing import Optional

from .conftest import get_unique_port
from .utils.helpers import (
    wait_for_proxy,
    wait_for_udp_port_bound,
    terminate_process,
    create_target_server,
    NEOPROXY_BINARY,
)
from .utils.certs import generate_test_certificates
from .utils.config_builders import (
    create_http3_listener_config,
    create_http3_chain_config,
)


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


class TestHttp3ChainProxyStatus:
    """http3_chain Proxy-Status header integration tests."""

    def test_connect_success_has_received_status(self) -> None:
        """
        H3C-PS-001: CONNECT success includes Proxy-Status with
        received-status=200.

        Target: Full chain Client -> http3_chain -> H3 upstream -> target
        returns 200 + proxy-status with received-status=200.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # Start a TCP target server
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

            # Start upstream proxy (H3 listener + connect_tcp)
            upstream_config_path = create_http3_listener_config(
                h3_port, cert_path, key_path, temp_dir
            )
            upstream_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound(
                "127.0.0.1", h3_port, timeout=10.0, proc=upstream_proc
            ), "Upstream proxy (H3) failed to start"

            # Start entry proxy (http3_chain -> H3 upstream)
            entry_config_path = create_http3_chain_config(
                http_port,
                [(addr, port, 1) for addr, port, _ in [("127.0.0.1", h3_port, 1)]],
                ca_path, temp_dir,
            )
            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", entry_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_proxy(
                "127.0.0.1", http_port, timeout=10.0, proc=entry_proc
            ), "Entry proxy (http3_chain) failed to start"

            # Send CONNECT via entry proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect(("127.0.0.1", http_port))
            sock.sendall(
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                f"\r\n".encode()
            )

            # Read response headers
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
            assert status == 200, \
                f"Expected 200, got {status}. Response: {response.decode(errors='ignore')[:200]}"

            # Verify Proxy-Status header
            ps = _get_header(response, "proxy-status")
            assert ps is not None, \
                f"Proxy-Status not found: {response.decode(errors='ignore')[:200]}"

            # Should have received-status=200 for upstream relay
            assert "received-status=200" in ps, \
                f"Expected received-status=200 in Proxy-Status: {ps}"
            assert "error=" not in ps, \
                f"Proxy-Status should not have error= on success: {ps}"

            # Upstream entry should be preserved (RFC 9209 append).
            # Proxy-Status identifiers use server local addresses.
            assert "received-status=200" in ps, \
                f"Expected received-status=200 in Proxy-Status: {ps}"
            assert ", " in ps, \
                f"Expected two Proxy-Status entries (upstream + entry): {ps}"

        finally:
            if entry_proc:
                terminate_process(entry_proc)
            if upstream_proc:
                terminate_process(upstream_proc)
            if target_socket:
                target_socket.close()
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_upstream_unreachable_has_error(self) -> None:
        """
        H3C-PS-002: Unresolvable upstream results in Proxy-Status
        dns_error.

        Target: When upstream hostname cannot be resolved, http3_chain
        returns 502 with Proxy-Status error=dns_error.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        _, _, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None

        try:
            # Point to an unresolvable hostname — resolve_address()
            # fails immediately (no QUIC timeout).
            config_content = f"""server_threads: 1

plugins:
  http3_chain:
    tls:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: this-host-does-not-exist.example.com:8443
            hostname: this-host-does-not-exist.example.com
            weight: 1

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{http_port}"]

services:
- name: http3_chain
  kind: http3_chain.http3_chain
  args:
    upstream: test_upstream

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: http3_chain
"""
            config_path = f"{temp_dir}/dns_error_config.yaml"
            with open(config_path, "w") as f:
                f.write(config_content)

            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_proxy(
                "127.0.0.1", http_port, timeout=10.0, proc=entry_proc
            ), "Entry proxy (http3_chain) failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("127.0.0.1", http_port))
            sock.sendall(
                b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n"
                b"Host: 127.0.0.1:80\r\n"
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

            assert response, \
                f"Empty response from proxy"

            status = _parse_status_code(response)
            assert status is not None, \
                f"Could not parse status. Response: {response.decode(errors='ignore')[:200]}"
            assert status == 502 or status == 503, \
                f"Expected 502 or 503, got {status}. Response: {response.decode(errors='ignore')[:200]}"

            ps = _get_header(response, "proxy-status")
            assert ps is not None, \
                f"Proxy-Status not found: {response.decode(errors='ignore')[:200]}"

            # DNS error -> error=dns_error
            assert "error=dns_error" in ps, \
                f"Expected error=dns_error in Proxy-Status: {ps}"

        finally:
            if entry_proc:
                terminate_process(entry_proc)
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_upstream_error_relayed_with_received_status(self) -> None:
        """
        H3C-PS-003: Upstream returns error, Proxy-Status has
        received-status.

        Target: When upstream proxy returns a non-success (e.g. 502),
        http3_chain relays the status and includes received-status.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # Start a target server on a different port - but DON'T start
            # a target on target_port. The upstream will try to connect
            # to target_port and fail.
            # This makes the upstream return 502.

            # Start upstream proxy (H3 listener + connect_tcp)
            upstream_config_path = create_http3_listener_config(
                h3_port, cert_path, key_path, temp_dir
            )
            upstream_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound(
                "127.0.0.1", h3_port, timeout=10.0, proc=upstream_proc
            ), "Upstream proxy (H3) failed to start"

            # Start entry proxy
            entry_config_path = create_http3_chain_config(
                http_port,
                [("127.0.0.1", h3_port, 1)],
                ca_path, temp_dir,
            )
            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", entry_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_proxy(
                "127.0.0.1", http_port, timeout=10.0, proc=entry_proc
            ), "Entry proxy (http3_chain) failed to start"

            # CONNECT to a port where nothing is listening
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect(("127.0.0.1", http_port))
            sock.sendall(
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n"
                f"\r\n".encode()
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
            # The upstream connect_tcp returns 502 on connection refused
            # http3_chain relays the upstream status as-is
            assert status == 502, \
                f"Expected 502, got {status}. Response: {response.decode(errors='ignore')[:200]}"

            ps = _get_header(response, "proxy-status")
            assert ps is not None, \
                f"Proxy-Status not found: {response.decode(errors='ignore')[:200]}"

            # Should preserve upstream error AND add our received-status.
            # Upstream connect_tcp sets Proxy-Status with error=connection_refused.
            # Entry http3_chain appends its entry with received-status.
            assert "error=connection_refused" in ps, \
                f"Expected error=connection_refused in Proxy-Status: {ps}"
            assert "received-status=502" in ps, \
                f"Expected received-status=502 in Proxy-Status: {ps}"
            assert ", " in ps, \
                f"Expected two Proxy-Status entries (upstream + entry): {ps}"

        finally:
            if entry_proc:
                terminate_process(entry_proc)
            if upstream_proc:
                terminate_process(upstream_proc)
            if target_socket:
                target_socket.close()
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
