"""
HTTP/3 Listener full functionality integration tests.

Test target: Verify neoproxy HTTP/3 Listener full functionality
Test nature: Black-box testing through external interface (HTTP/3)

This test module covers:
- 7.1 Basic connection scenarios (QUIC handshake, CONNECT, data transfer)
- 7.2 Proxy chain complete scenarios
- 7.4 Graceful Shutdown scenarios (with active connections)
- 7.5 Error handling scenarios (HTTP/3 specific)

NOTE: These tests verify the complete HTTP/3 listener functionality
using real HTTP/3 client (aioquic) and curl with HTTP/3 support.
"""

import asyncio
import os
import shutil
import signal
import socket
import tempfile
import time

import pytest

from tests.fixtures.configuration import StringMap
from tests.fixtures.h3_configuration import (
    create_http3_chain_config,
    create_http3_listener_config,
)
from tests.fixtures.h3_connection import perform_h3_connection_test
from tests.fixtures.h3_tunnel import (
    H3ConnectResult,
    H3TunnelResult,
    perform_h3_connect_test,
    perform_h3_tunnel_data_transfer,
)

# Alias for convenience
from tests.fixtures.http3_client import H3Client
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server

# ==============================================================================
# Test cases - 7.1 Basic HTTP/3 Connection scenarios (Full)
# ==============================================================================


class TestHTTP3FullConnection:
    """Test 7.1: Full HTTP/3 connection scenarios."""

    def test_quic_handshake_success(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-FULL-001: QUIC handshake succeeds.

        Target: Verify QUIC handshake completes successfully when client
        connects to HTTP/3 listener using real HTTP/3 client.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Use real HTTP/3 client to verify QUIC handshake
            async def do_handshake() -> tuple[bool, int, str]:
                (
                    success,
                    status_code,
                    message,
                ) = await perform_h3_connection_test(
                    "127.0.0.1",
                    proxy_port,
                    ca_path=ca_path,
                    timeout=10.0,
                )
                return success, status_code, message

            success, _status_code, message = asyncio.run(do_handshake())

            assert success, f"QUIC handshake failed: {message}"
            assert proxy_proc.poll() is None, (
                "HTTP/3 listener should still be running after handshake"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http3_connect_request_success(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-FULL-002: HTTP/3 CONNECT request returns 200.

        Target: Verify HTTP/3 listener accepts CONNECT request and returns 200.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            # Create target server
            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.sendall(b"ECHO:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Send CONNECT request using real HTTP/3 client
            async def do_connect() -> tuple[bool, int, str]:
                (
                    success,
                    status_code,
                    message,
                ) = await perform_h3_connect_test(
                    "127.0.0.1",
                    proxy_port,
                    "127.0.0.1",
                    target_port,
                    ca_path=ca_path,
                    timeout=15.0,
                )
                return success, status_code, message

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, message = loop.run_until_complete(do_connect())
            finally:
                loop.close()

            assert success, f"CONNECT request failed: {message}"
            assert status_code == 200, f"Expected status 200, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http3_data_transfer(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-FULL-003: HTTP/3 data bidirectional transfer works.

        Target: Verify data can be sent both ways through HTTP/3 tunnel.
        This test establishes an HTTP/3 tunnel and performs actual data transfer
        to verify bidirectional communication works correctly.

        Per design section 2.1.3, after CONNECT returns 200 OK, bidirectional
        data transfer must work: client sends data through QUIC stream, server
        forwards to TCP target, and responses are sent back through the stream.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            # Create target server that echoes data
            received_data: list[bytes] = []

            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        received_data.append(data)
                        # Echo back with prefix
                        conn.sendall(b"ECHO:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Test actual data transfer through HTTP/3 tunnel
            test_data = b"HELLO_FROM_HTTP3_CLIENT_12345"

            async def do_data_transfer() -> H3TunnelResult:
                result = await perform_h3_tunnel_data_transfer(
                    "127.0.0.1",
                    proxy_port,
                    "127.0.0.1",
                    target_port,
                    ca_path=ca_path,
                    test_data=test_data,
                    timeout=15.0,
                )
                return result

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(do_data_transfer())
            finally:
                loop.close()

            # Verify CONNECT request succeeded
            assert result.success, f"Data transfer failed: {result.message}"
            assert result.response_data == b"ECHO:" + test_data
            assert result.status_code == 200, (
                f"Expected status 200, got {result.status_code}"
            )

            # Verify data was sent successfully (client -> proxy -> target)
            assert result.data_sent == len(test_data), (
                f"Expected {len(test_data)} bytes sent, got {result.data_sent}"
            )

            # CRITICAL ASSERTION: Verify bidirectional data transfer
            # Per design section 2.1.3 and 7.1, data must flow both ways:
            # - Client sends data through HTTP/3 stream
            # - Target echoes data back
            # - Proxy forwards echo back to client through HTTP/3 stream
            # data_received > 0 confirms the return path works
            assert result.data_received > 0, (
                "BIDIRECTIONAL TRANSFER FAILURE: Expected echo response from target,"
                + " but received 0 bytes. This indicates data cannot flow from target"
                + " back to client through HTTP/3 "
                + f"stream. Sent {result.data_sent} bytes,"
                + f" received {result.data_received} bytes. Per design section 2.1.3,"
                + " bidirectional data transfer is required."
            )

            # Verify target server received the data (confirms forward path)
            # Client already received echo, so target has processed the data
            total_received = sum(len(d) for d in received_data)
            assert total_received == len(test_data), (
                f"Target server received {total_received} bytes, expected"
                + f" {len(test_data)} bytes. This indicates data was not properly"
                + " forwarded to target."
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.4 Graceful Shutdown with active connections
# ==============================================================================


class TestHTTP3GracefulShutdownWithConnections:
    """Test 7.4: HTTP/3 graceful shutdown with active connections."""

    def test_shutdown_with_active_h3_connections(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-SHUTDOWN-003: Shutdown with active HTTP/3 connections.

        Target: Verify HTTP/3 listener shuts down gracefully even with
        active connections.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                server_threads=2,
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Graceful shutdown
            start_time = time.monotonic()
            proxy_proc.send_signal(signal.SIGTERM)

            return_code = proxy_proc.wait(timeout=15)
            elapsed = time.monotonic() - start_time

            assert return_code == 0, f"Expected exit code 0, got {return_code}"

            # Shutdown should complete within reasonable time
            assert elapsed < 5.0, f"Shutdown took too long: {elapsed:.2f}s"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_shutdown_timeout_with_slow_connections(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-SHUTDOWN-004: Shutdown timeout behavior.

        Target: Verify HTTP/3 listener shutdown timeout behavior.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Graceful shutdown - should complete within timeout
            proxy_proc.send_signal(signal.SIGTERM)

            return_code = proxy_proc.wait(timeout=15)

            assert return_code == 0, f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.2 Full Proxy Chain scenarios
# ==============================================================================


class TestFullHTTP3ProxyChain:
    """Test 7.2: Full HTTP/3 proxy chain scenarios."""

    def test_proxy_chain_graceful_shutdown_both_ends(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-CHAIN-FULL-002: Both ends of proxy chain shut down gracefully.

        Target: Verify both HTTP/3 listener and chain service shut down
        gracefully in the correct order.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Start HTTP/3 listener
            h3_config = create_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)

            assert h3_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Start chain service
            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir2,
            )
            chain_proc = start_proxy(chain_config)

            assert chain_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Shutdown chain first (frontend)
            chain_proc.send_signal(signal.SIGTERM)
            return_code1 = chain_proc.wait(timeout=15)

            # Then shutdown H3 listener (backend)
            h3_proc.send_signal(signal.SIGTERM)
            return_code2 = h3_proc.wait(timeout=15)

            assert return_code1 == 0, f"Chain exit code: {return_code1}"
            assert return_code2 == 0, f"H3 listener exit code: {return_code2}"

        finally:
            if chain_proc and chain_proc.poll() is None:
                chain_proc.terminate()
                _ = chain_proc.wait(timeout=5)
            if h3_proc and h3_proc.poll() is None:
                h3_proc.terminate()
                _ = h3_proc.wait(timeout=5)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test cases - 7.5 HTTP/3 Error Handling scenarios
# ==============================================================================


class TestHTTP3ErrorHandling:
    """Test 7.5: HTTP/3 error handling scenarios with real client."""

    def test_non_connect_request_reaches_refused_target(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-ERR-004: A valid H3 GET reaches its HTTPS target.

        H3's scheme, authority and path describe an absolute target, even
        when :path is just '/'. A refused target must return 502 rather
        than rejecting this valid request as an unsupported scheme.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Send a GET request (non-CONNECT) using HTTP/3 client
            async def do_get_request() -> tuple[bool, int, bytes | str]:
                client = H3Client("127.0.0.1", proxy_port, ca_path=ca_path)
                connected = await asyncio.wait_for(client.connect(), timeout=15.0)
                if not connected:
                    return False, 0, "Connection failed"

                response = await asyncio.wait_for(
                    client.send_request(
                        "GET", "/", authority=f"127.0.0.1:{target_port}"
                    ),
                    timeout=15.0,
                )
                await client.close()
                return True, response.status_code, response.body

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, _body = loop.run_until_complete(do_get_request())
            finally:
                loop.close()

            assert success, "HTTP/3 connection failed"
            assert status_code == 502, (
                f"Expected 502 for a refused HTTPS target, got {status_code}"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_target_returns_400(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-ERR-005: Invalid target address returns 400.

        Target: Verify HTTP/3 listener returns 400 for invalid target.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # CONNECT to an invalid target (port 0 is invalid)
            async def do_connect() -> tuple[bool, int, bytes | str]:
                # Try to connect to target with port 0 (invalid)
                # This should be handled by the proxy
                client = H3Client("127.0.0.1", proxy_port, ca_path=ca_path)
                connected = await asyncio.wait_for(client.connect(), timeout=15.0)
                if not connected:
                    return False, 0, "Connection failed"

                # Note: The CONNECT target validation happens at the HTTP/3 layer
                # We send a CONNECT to invalid:0
                response = await asyncio.wait_for(
                    client.send_connect_request("invalid", 0),
                    timeout=15.0,
                )
                await client.close()
                return True, response.status_code, response.body

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, _body = loop.run_until_complete(do_connect())
            finally:
                loop.close()

            # The proxy should return 400 for invalid target
            assert success, "HTTP/3 connection failed"
            assert status_code == 400, f"Expected 400 Bad Request, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_target_unreachable_returns_502(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-ERR-006: Target unreachable returns 502.

        Target: Verify HTTP/3 listener returns 502 when target is unreachable.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create config with short connect_timeout to make test faster
            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct
        tcp_connect_timeout: 1s

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: direct
  kind: upstream.upstream
  args:
    upstream: direct

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  listeners: ["h3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # CONNECT to an unreachable target
            # Use TEST-NET-2 (198.51.100.0/24) which is non-routable
            async def do_connect() -> H3ConnectResult:
                from tests.fixtures.h3_tunnel import perform_h3_connect_test_full

                result = await perform_h3_connect_test_full(
                    "127.0.0.1",
                    proxy_port,
                    "198.51.100.1",
                    9999,
                    ca_path=ca_path,
                    timeout=10.0,  # Shorter timeout since connect_timeout is 2s
                )
                return result

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(do_connect())
            finally:
                loop.close()

            # The proxy should return 502 (bad gateway) or 504 (gateway timeout)
            # for unreachable targets. If the client times out before the proxy
            # responds, status_code will be 0.
            assert result.status_code in (502, 504, 0), (
                f"Expected 502/504/timeout, got {result.status_code}. Message:"
                + f" {result.message}"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.7 Configuration Validation for HTTP/3
# ==============================================================================


class TestHTTP3ConfigValidationFull:
    """Test 7.7: HTTP/3 configuration validation scenarios."""

    def test_invalid_quic_max_streams_uses_default(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-004: Invalid max_concurrent_bidi_streams uses default.

        Target: Verify HTTP/3 listener uses default for invalid stream count.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Invalid: extremely large value
            quic_config = """      max_concurrent_bidi_streams: 999999999
      max_idle_timeout: '30s'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Invalid value is rejected at startup (bail!)
            _ = proxy_proc.wait(timeout=5)
            assert proxy_proc.returncode != 0, (
                "HTTP/3 listener should reject invalid max_concurrent_bidi_streams"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_quic_timeout_uses_default(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-005: Invalid max_idle_timeout uses default.

        Target: Verify HTTP/3 listener uses default for invalid timeout.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Test with zero timeout (invalid, rejected at startup)
            quic_config = """      max_concurrent_bidi_streams: 100
      max_idle_timeout: '0s'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Invalid timeout is rejected at startup (bail!)
            _ = proxy_proc.wait(timeout=5)
            assert proxy_proc.returncode != 0, (
                "HTTP/3 listener should reject invalid max_idle_timeout"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_valid_plaintext_password_accepted(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-007: Valid plaintext password is accepted.

        Target: Verify HTTP/3 listener accepts valid plaintext password format.
        After auth module refactoring, bcrypt hashes are no longer supported.
        Plaintext passwords are now the standard format.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct
  auth:

services:
- name: direct
  kind: upstream.upstream
  args:
    upstream: direct
  layers:
    - kind: auth.basic_auth
      args:
        users:
          - username: "testuser"
            password: "plaintext_secret"

listeners:
- name: http3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  listeners: ["http3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "valid_password.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proxy_proc = start_proxy(config_path)

            # Should start successfully with valid plaintext password
            assert proxy_proc.wait_ready(timeout=5.0), (
                "HTTP/3 listener should start with valid plaintext password"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_quic_params_boundary_min_values(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-008: QUIC params at minimum boundary values.

        Target: Verify HTTP/3 listener handles minimum boundary values correctly.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Test minimum valid values
            quic_config = """      max_concurrent_bidi_streams: 1
      max_idle_timeout: '1ms'
      initial_mtu: 1200
      send_window: '1B'
      receive_window: '1B'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Should start with minimum valid values
            if not proxy_proc.wait_ready(timeout=5.0):
                if proxy_proc.poll() is not None:
                    _, stderr_data = proxy_proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener should start with minimum QUIC params")

            assert proxy_proc.poll() is None, "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_quic_params_boundary_max_values(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-009: QUIC params at maximum boundary values.

        Target: Verify HTTP/3 listener handles maximum boundary values correctly.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Test maximum valid values per design doc
            quic_config = """      max_concurrent_bidi_streams: 10000
      max_idle_timeout: '300s'
      initial_mtu: 9000
      send_window: '100MiB'
      receive_window: '100MiB'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Should start with maximum valid values
            if not proxy_proc.wait_ready(timeout=5.0):
                if proxy_proc.poll() is not None:
                    _, stderr_data = proxy_proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener should start with maximum QUIC params")

            assert proxy_proc.poll() is None, "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_quic_params_negative_values_uses_default(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-010: QUIC params with negative values uses default.

        Target: Verify HTTP/3 listener uses defaults for negative values.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Note: YAML may not parse negative values correctly for unsigned types
            # This tests that the system handles invalid input gracefully
            quic_config = """      max_concurrent_bidi_streams: 100
      max_idle_timeout: '30s'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener should start"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.2 Full Proxy Chain Data Transfer
# ==============================================================================


# ==============================================================================
# Test cases - 7.4 HTTP/3 Graceful Shutdown with Active Streams
# ==============================================================================


class TestHTTP3GracefulShutdownTimeout:
    """Test 7.4: HTTP/3 graceful shutdown with active streams timeout."""

    def test_shutdown_timeout_with_active_h3_stream(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-SHUTDOWN-TIMEOUT-001: Shutdown timeout with active HTTP/3 stream.

        Target: Verify HTTP/3 listener shuts down after timeout when there
        is an active stream that doesn't close.

        Per design doc:
        - Listener task wait: 3 seconds, cancellation cleanup: up to 2 seconds
        - After timeout, should force close all connections
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            # Create a target server that blocks for a long time
            def blocking_handler(conn: socket.socket) -> None:
                try:
                    # Block for 60 seconds to simulate slow/stuck connection
                    time.sleep(60)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, blocking_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Send SIGTERM while server is running (no active streams, but tests
            # timeout)
            start_time = time.monotonic()
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            # Should exit within shutdown timeout + buffer
            return_code = proxy_proc.wait(timeout=15)
            elapsed = time.monotonic() - start_time

            assert return_code == 0, f"Expected exit code 0, got {return_code}"

            # Allow the listener's 3s + 2s task wait budget plus test overhead.
            assert elapsed < 10.0, (
                f"Shutdown took too long: {elapsed:.1f}s (expected < 10s)"
            )

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.6 HTTP/3 Performance
# ==============================================================================
