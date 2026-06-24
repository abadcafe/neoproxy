"""
Tunnel idle timeout integration tests.

Test target: Verify that tunnel idle timeout works correctly —
connections are only closed when no data flows in EITHER direction
for the configured timeout period.

This module covers:
- Tunnel survives sustained data transfer longer than max_idle_timeout
- Tunnel times out when no data flows
- Tunnel max_idle_timeout is configurable
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time

from .conftest import get_unique_port
from .types import (
    BytesProcess,
    StringMap,
)
from .utils.config_builders import (
    create_http3_listener_config,
)
from .utils.helpers import (
    create_target_server,
    start_proxy,
    wait_for_proxy,
    wait_for_udp_port_bound,
)


class TestTunnelIdleTimeout:
    """Test tunnel idle timeout behavior through the full proxy chain."""

    def test_tunnel_survives_sustained_transfer(self, shared_test_certs: StringMap) -> None:
        """
        TC-IDLE-001: Tunnel survives data transfer longer than max_idle_timeout.

        Target: Verify that a tunnel is NOT killed by max_idle_timeout while
        data is actively flowing, even if the transfer takes longer than
        the configured max_idle_timeout (default 60s).

        The old implementation used `tokio::time::timeout(60s)` which
        killed the tunnel after 60s total, regardless of data flow.
        The new implementation uses true idle timeout — only closing
        when no data flows for the timeout period.

        We use a short max_idle_timeout (2s) and transfer data for >2s
        to verify the tunnel stays alive.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create a target server that sends data slowly (longer than max_idle_timeout)
            # It sends 5 chunks of 1KB every 500ms, taking ~2.5s total
            def slow_handler(conn: socket.socket) -> None:
                try:
                    # Read the HTTP request first
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        data = conn.recv(4096)
                        if not data:
                            return
                        buf += data

                    # Send HTTP response headers
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/octet-stream\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"\r\n"
                    )

                    # Send data in chunks over time
                    chunk = b"A" * 1024
                    for _ in range(5):
                        chunk_header = f"{len(chunk):x}\r\n".encode()
                        conn.sendall(chunk_header + chunk + b"\r\n")
                        time.sleep(0.5)

                    # Final chunk
                    conn.sendall(b"0\r\n\r\n")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, slow_handler)

            # Start HTTP/3 listener
            h3_config = create_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0, proc=h3_proc), (
                "HTTP/3 listener failed to start"
            )

            # Start chain service with short max_idle_timeout
            # This config includes max_idle_timeout: 2s
            config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1
            tunnel_idle_timeout: "2s"
            http3: {{}}

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{http_port}"]

services:
- name: upstream
  kind: http_upstream.upstream
  args:
    upstream: test_upstream

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: upstream
"""
            config_path = os.path.join(temp_dir2, "chain_config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            chain_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0, proc=chain_proc), "HTTP listener failed to start"

            # Download through the proxy — should succeed even though
            # transfer takes ~2.5s and max_idle_timeout is 2s
            start = time.time()
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-p",
                    "-x",
                    f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "15",
                ],
                capture_output=True,
                text=True,
            )
            elapsed = time.time() - start

            # The download should succeed — data was flowing the entire time
            assert result.returncode == 0, (
                f"curl failed with code {result.returncode}: stdout={result.stdout}, stderr={result.stderr}"
            )

            # Verify we received the expected amount of data (5 * 1024 = 5120 bytes)
            assert len(result.stdout) == 5120, f"Expected 5120 bytes, got {len(result.stdout)}"

            # Verify the transfer actually took longer than max_idle_timeout
            assert elapsed >= 2.0, f"Transfer should take longer than max_idle_timeout (2s), took {elapsed:.1f}s"

        finally:
            if chain_proc:
                chain_proc.kill()
                chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_tunnel_times_out_when_idle(self, shared_test_certs: StringMap) -> None:
        """
        TC-IDLE-002: Tunnel times out when no data flows.

        Target: Verify that a tunnel IS killed by max_idle_timeout when
        no data flows for the configured period.

        We establish a CONNECT tunnel and then don't send any data.
        The tunnel should close after max_idle_timeout.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create target server that accepts but does nothing
            def idle_handler(conn: socket.socket) -> None:
                try:
                    time.sleep(30)  # Just sit there
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, idle_handler)

            # Start HTTP/3 listener
            h3_config = create_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0, proc=h3_proc), (
                "HTTP/3 listener failed to start"
            )

            # Start chain service with short max_idle_timeout
            config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1
            tunnel_idle_timeout: "2s"
            http3: {{}}

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{http_port}"]

services:
- name: upstream
  kind: http_upstream.upstream
  args:
    upstream: test_upstream

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: upstream
"""
            config_path = os.path.join(temp_dir2, "chain_config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            chain_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0, proc=chain_proc), "HTTP listener failed to start"

            # Use raw socket to establish CONNECT and then idle
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("127.0.0.1", http_port))

            # Send CONNECT request
            sock.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode())

            # Read the 200 OK response
            response = b""
            while b"\r\n\r\n" not in response:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            assert b"200" in response, f"Expected 200 OK from CONNECT, got: {response!r}"

            # Now idle — don't send any data
            # The tunnel should close after max_idle_timeout (2s)
            start = time.time()
            sock.settimeout(10)
            try:
                data = sock.recv(4096)
                # Connection closed by idle timeout
            except socket.timeout:
                pass

            elapsed = time.time() - start
            sock.close()

            # Connection should have been closed within a reasonable time
            # after max_idle_timeout (2s), not stay open forever
            assert elapsed < 8.0, f"Idle tunnel should be closed after ~2s, but stayed open for {elapsed:.1f}s"

        finally:
            if chain_proc:
                chain_proc.kill()
                chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_tunnel_unidirectional_transfer_no_false_timeout(self, shared_test_certs: StringMap) -> None:
        """
        TC-IDLE-003: Unidirectional transfer does not cause false idle timeout.

        Target: Verify the stale alarm fix — when data flows in only one
        direction (e.g. server→client download), the other direction's
        idle Sleep may fire but should be caught by the is_idle()
        secondary check against the shared tracker.

        We use a short max_idle_timeout (2s) and have the server send data
        continuously for 5s. The client never sends data back. Without
        the stale alarm fix, the client's read Sleep might fire after
        2s (since client never writes), but the shared tracker shows
        recent activity (from server writes), so the tunnel should
        survive.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Server sends data continuously for 5s, client never sends back
            def one_way_handler(conn: socket.socket) -> None:
                try:
                    # Read HTTP request
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        data = conn.recv(4096)
                        if not data:
                            return
                        buf += data

                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/octet-stream\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"\r\n"
                    )

                    # Send 10KB chunks every 200ms for 5s
                    chunk = b"B" * 10240
                    for _ in range(25):
                        chunk_header = f"{len(chunk):x}\r\n".encode()
                        conn.sendall(chunk_header + chunk + b"\r\n")
                        time.sleep(0.2)

                    conn.sendall(b"0\r\n\r\n")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, one_way_handler)

            # Start HTTP/3 listener
            h3_config = create_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0, proc=h3_proc), (
                "HTTP/3 listener failed to start"
            )

            # Start chain service with 2s max_idle_timeout
            config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1
            tunnel_idle_timeout: "2s"
            http3: {{}}

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{http_port}"]

services:
- name: upstream
  kind: http_upstream.upstream
  args:
    upstream: test_upstream

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: upstream
"""
            config_path = os.path.join(temp_dir2, "chain_config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            chain_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0, proc=chain_proc), "HTTP listener failed to start"

            # Download through the proxy — one-way transfer lasting 5s
            # with 2s max_idle_timeout. Without stale alarm fix, this would fail.
            start = time.time()
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-p",
                    "-x",
                    f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "15",
                ],
                capture_output=True,
                text=True,
            )
            elapsed = time.time() - start

            assert result.returncode == 0, (
                f"curl failed with code {result.returncode}: stdout={result.stdout[:200]}, stderr={result.stderr}"
            )

            # Should have received all the data (25 * 10240 = 256000 bytes)
            assert len(result.stdout) == 256000, f"Expected 256000 bytes, got {len(result.stdout)}"

            # Transfer took >2s (the max_idle_timeout), proving no false timeout
            assert elapsed >= 4.0, f"Transfer should take ~5s, only took {elapsed:.1f}s"

        finally:
            if chain_proc:
                chain_proc.kill()
                chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
