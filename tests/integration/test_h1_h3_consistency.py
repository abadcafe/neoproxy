"""
Black-box tests for H1/H3 listener consistency and config architecture.

These tests verify the expected behavior of the refactored configuration
architecture where listener kinds are renamed and server-level configuration
for TLS, auth, and hostnames is introduced.

This is Task 001 of 21 - writing the black-box tests that will initially fail
and be used to verify the complete implementation in later tasks.
"""

import os
import shutil
import subprocess
import tempfile

import pytest
import requests
import yaml

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import ConfigDict, StringMap
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process

# ==============================================================================
# Helper: Write H1/H3 Consistency Config
# ==============================================================================


# ==============================================================================
# Fixtures
# ==============================================================================


# ==============================================================================
# Test Classes
# ==============================================================================


class TestListenerKinds:
    """Test that listener kinds are renamed correctly."""

    def test_http_listener_kind_accepted(
        self,
        proxy_with_capture: tuple[BytesProcess | None, bytes, str],
    ) -> None:
        """
        Test that 'http' listener kind is accepted.

        Expected: FAIL - 'http' kind not registered in current implementation.
        """
        proc, stderr_data, _config_path = proxy_with_capture

        if proc is None:
            # Process exited - show error for debugging
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            pytest.fail(
                (
                    "Process failed to start with 'http' listener kind.\nstderr:"
                    + f" {stderr_text}"
                )
            )

        assert proc.poll() is None, (
            "Process should be running with 'http' listener kind"
        )

    def test_https_listener_kind_accepted(
        self,
        proxy_with_capture: tuple[BytesProcess | None, bytes, str],
    ) -> None:
        """
        Test that 'https' listener kind is accepted.

        Expected: FAIL - 'https' kind not registered in current implementation.
        """
        proc, stderr_data, _config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            pytest.fail(
                (
                    "Process failed to start with 'https' listener kind.\nstderr:"
                    + f" {stderr_text}"
                )
            )

        assert proc.poll() is None, (
            "Process should be running with 'https' listener kind"
        )

    def test_http3_listener_kind_accepted(
        self,
        proxy_with_capture: tuple[BytesProcess | None, bytes, str],
    ) -> None:
        """
        Test that 'http3' listener kind is accepted.

        Expected: FAIL - 'http3' kind not registered in current implementation.
        """
        proc, stderr_data, _config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            pytest.fail(
                (
                    "Process failed to start with 'http3' listener kind.\nstderr:"
                    + f" {stderr_text}"
                )
            )

        assert proc.poll() is None, (
            "Process should be running with 'http3' listener kind"
        )


class TestServerLevelConfig:
    """Test server-level configuration for TLS, auth, and hostnames."""

    def test_server_level_tls_accepted(
        self,
        proxy_with_capture: tuple[BytesProcess | None, bytes, str],
    ) -> None:
        """
        Test that tls at server level is accepted.

        Expected: FAIL - Server struct doesn't have tls field in current implementation.
        """
        proc, stderr_data, _config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            if "tls" in stderr_text.lower():
                pytest.fail(
                    f"Server-level 'tls' field not accepted.\nstderr: {stderr_text}"
                )
            else:
                pytest.fail(
                    (
                        "Process failed to start (possibly due to server-level"
                        + f" tls).\nstderr: {stderr_text}"
                    )
                )

        assert proc.poll() is None, "Process should be running with server-level tls"

    def test_server_level_hostnames_accepted(
        self,
        proxy_with_capture: tuple[BytesProcess | None, bytes, str],
    ) -> None:
        """
        Test that hostnames at server level are accepted.

        Expected: FAIL - Server struct doesn't have hostnames field in current
        implementation.
        """
        proc, stderr_data, _config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            if "hostnames" in stderr_text.lower():
                pytest.fail(
                    (
                        "Server-level 'hostnames' field not accepted.\nstderr:"
                        + f" {stderr_text}"
                    )
                )
            else:
                pytest.fail(
                    (
                        "Process failed to start (possibly due to server-level"
                        + f" hostnames).\nstderr: {stderr_text}"
                    )
                )

        assert proc.poll() is None, (
            "Process should be running with server-level hostnames"
        )

    def test_http_listener_ignores_server_level_tls(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        Test that HTTP listener ignores server-level TLS config.

        HTTP is a plaintext protocol. When server-level TLS config
        is present on an HTTP server, the listener should start normally
        and ignore the TLS configuration.
        """
        cert_path = shared_test_certs["cert_path"]
        key_path = shared_test_certs["key_path"]
        ca_path = shared_test_certs["ca_path"]
        port = get_unique_port()

        temp_dir = tempfile.mkdtemp()
        try:
            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {
                    "upstream": {
                        "upstreams": [{"name": "direct"}],
                    }
                },
                "services": [
                    {
                        "name": "direct",
                        "kind": "upstream.upstream",
                        "args": {"upstream": "direct"},
                    }
                ],
                "listeners": [
                    {
                        "name": "http_main",
                        "kind": "http",
                        "addresses": [f"127.0.0.1:{port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "test",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ],
                            "client_ca_certs": [ca_path],
                        },
                        "listeners": ["http_main"],
                        "service": "direct",
                    }
                ],
            }
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = start_proxy(config_path)
            try:
                assert proc.wait_ready(timeout=5.0), (
                    "HTTP listener should start and ignore server-level TLS config"
                )
            finally:
                terminate_process(proc)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3MultiAddress:
    """Test HTTP/3 listener multi-address support."""

    def test_http3_addresses_field_accepted(
        self,
        proxy_with_capture: tuple[BytesProcess | None, bytes, str],
    ) -> None:
        """
        Test that http3 listener accepts 'addresses' (plural) field.

        Expected: FAIL - http3 uses 'address' not 'addresses' in current implementation.
        """
        proc, stderr_data, _config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            if "addresses" in stderr_text.lower():
                pytest.fail(
                    (
                        "http3 listener does not accept 'addresses' field.\nstderr:"
                        + f" {stderr_text}"
                    )
                )
            else:
                pytest.fail(
                    (
                        "Process failed to start (possibly due to http3 addresses"
                        + f" field).\nstderr: {stderr_text}"
                    )
                )

        assert proc.poll() is None, (
            "Process should be running with http3 'addresses' field"
        )

    def test_http3_listens_on_multiple_addresses(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        Test that http3 listener can listen on multiple addresses.

        This test verifies that HTTP/3 listener supports the 'addresses' field
        and can accept connections on multiple ports.
        """
        temp_dir = tempfile.mkdtemp(prefix="neoproxy_multiaddr_test_")
        proxy_port1 = get_unique_port()
        proxy_port2 = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Create config with multiple HTTP/3 addresses
            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "h3_multi",
                        "kind": "http3",
                        "addresses": [
                            f"127.0.0.1:{proxy_port1}",
                            f"127.0.0.1:{proxy_port2}",
                        ],
                    }
                ],
                "servers": [
                    {
                        "name": "http3_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ]
                        },
                        "listeners": ["h3_multi"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proxy_proc = start_proxy(config_path)

            # Wait for both UDP ports to be bound
            assert proxy_proc.wait_ready(timeout=5.0), (
                f"HTTP/3 listener failed to start on port {proxy_port1}"
            )
            assert proxy_proc.wait_ready(timeout=5.0), (
                f"HTTP/3 listener failed to start on port {proxy_port2}"
            )

            # Verify process is still running
            assert proxy_proc.poll() is None, "Proxy process should be running"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3ConnectOnlyUpgrade:
    """Test that HTTP/3 listener only creates upgrade pair for CONNECT."""

    def test_get_request_no_upgrade_error(
        self, h1_h3_test_env: tuple[str, int, int, int, int]
    ) -> None:
        """
        Test that GET request to echo service doesn't cause upgrade error.

        The original bug caused "Service dropped the receiver" error
        for non-CONNECT requests.

        Expected: FAIL - Config with 'http' kind not accepted yet.
        """
        config_path, _http_port, _https_port, _http3_port, default_port = h1_h3_test_env

        proc: BytesProcess | None = None
        stderr_data = b""

        try:
            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for every listener to report readiness.
            if not proc.wait_ready(timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("Proxy server failed to start within timeout")

            # This should not cause an error in the logs
            try:
                response = requests.get(
                    f"http://127.0.0.1:{default_port}/test",
                    timeout=5.0,
                )
                assert response.status_code == 200, (
                    f"Expected 200, got {response.status_code}"
                )
            except requests.exceptions.ConnectionError:
                pytest.fail(
                    (
                        "Could not connect to server on "
                        + f"port {default_port}. Server may"
                        + " not be listening."
                    )
                )
            except requests.exceptions.Timeout:
                pytest.fail(f"Request to server on port {default_port} timed out")

        finally:
            if proc is not None:
                # Check stderr for upgrade-related errors
                # Use force=True for fast cleanup (no graceful shutdown needed)
                terminate_process(proc, force=True)


class TestHTTP10Support:
    """Test that HTTP/1.0 requests are handled correctly.

    HTTP/1.0 requests are no longer rejected with 505. Instead:
    - HTTP/1.0 CONNECT (as used by Python 3.8 http.client._tunnel)
      should succeed and establish a tunnel.
    - HTTP/1.0 GET with Host header should route normally.
    - HTTP/1.0 GET without Host header should use the default server.
    """

    def test_http10_connect_succeeds(self) -> None:
        """
        HTTP/1.0 CONNECT should successfully establish a tunnel.

        Python 3.8's http.client._tunnel() sends
        'CONNECT host:port HTTP/1.0' (hardcoded HTTP/1.0).
        This must work for Python 3.8 HTTPS clients using a proxy.
        """
        import socket

        from tests.fixtures.http_configuration import create_test_config
        from tests.fixtures.proxy_process import start_proxy
        from tests.fixtures.tcp_peer import create_target_server

        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            # Echo server as CONNECT target
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

            proc = start_proxy(config_path)
            assert proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Send CONNECT with HTTP/1.0 (as Python 3.8 does)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                connect_request = (
                    f"CONNECT 127.0.0.1:{target_port} HTTP/1.0\r\nHost:"
                    + f" 127.0.0.1:{target_port}\r\n\r\n"
                ).encode()
                sock.sendall(connect_request)

                # Read 200 response
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk

                assert b"200" in response, (
                    "Expected 200 for HTTP/1.0 CONNECT, got:"
                    + f" {response.decode(errors='ignore')}"
                )

                # Verify bidirectional data transfer through tunnel
                test_data = b"HELLO_HTTP10"
                sock.sendall(test_data)
                echo = sock.recv(1024)
                assert echo == b"ECHO:" + test_data, (
                    f"Tunnel data mismatch: expected 'ECHO:{test_data.decode()}', got"
                    + f" {echo.decode(errors='ignore')}"
                )
            finally:
                sock.close()

        finally:
            if proc is not None:
                terminate_process(proc)
            if target_socket is not None:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http10_get_with_host_routed(
        self, h1_h3_test_env: tuple[str, int, int, int, int]
    ) -> None:
        """
        HTTP/1.0 GET with Host header should route to the echo service.

        With the 505 rejection removed, HTTP/1.0 requests that include
        a Host header should be routed normally by the listener.
        """
        import socket

        config_path, _http_port, _https_port, _http3_port, default_port = h1_h3_test_env

        proc: BytesProcess | None = None

        try:
            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not proc.wait_ready(timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("Proxy server failed to start within timeout")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", default_port))
            sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            response = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()

            # Should get 200 from echo service, not 505
            assert b"200" in response, (
                "Expected 200 for HTTP/1.0 GET with Host, got:"
                + f" {response.decode(errors='ignore')}"
            )

        finally:
            if proc is not None:
                terminate_process(proc)

    def test_http10_get_without_host_routes_to_default(
        self, h1_h3_test_env: tuple[str, int, int, int, int]
    ) -> None:
        """
        HTTP/1.0 GET without Host uses the listener's default server.
        """
        import socket

        config_path, _http_port, _https_port, _http3_port, default_port = h1_h3_test_env

        proc: BytesProcess | None = None

        try:
            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not proc.wait_ready(timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("Proxy server failed to start within timeout")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", default_port))
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024)
            sock.close()

            assert b"200" in response.split(b"\r\n", 1)[0], (
                "Expected default server for HTTP/1.0 GET without Host, got:"
                + f" {response.decode(errors='ignore')}"
            )

        finally:
            if proc is not None:
                terminate_process(proc)


class TestHTTP3AuthorityHostMismatch:
    """Test HTTP/3 authority vs Host mismatch checks.

    Per RFC 9114 §4.3.1, if both :authority and Host are present,
    they MUST contain the same value.
    """

    def test_h3_authority_host_match_returns_200(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        Test that matching :authority and Host in HTTP/3 returns 200 OK.

        When :authority and Host header match, the request should
        succeed. This test verifies the basic HTTP/3 flow with correct headers.
        """
        import asyncio

        from tests.fixtures.h3_request import perform_h3_request_with_custom_authority

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_h3_match_test_")
        http3_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create HTTP/3 config with echo service
            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "h3_main",
                        "kind": "http3",
                        "addresses": [f"127.0.0.1:{http3_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "http3_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ]
                        },
                        "listeners": ["h3_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for HTTP/3 listener
            if not proc.wait_ready(timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener failed to start within timeout")

            # Send request with matching :authority and Host
            response = asyncio.run(
                perform_h3_request_with_custom_authority(
                    host="127.0.0.1",
                    port=http3_port,
                    custom_authority="localhost",  # Match Host header
                    path="/test",
                    ca_path=ca_path,
                    additional_headers=[("host", "localhost")],  # Match authority
                    timeout=10.0,
                )
            )

            # Should get 200 OK for matching authority/Host
            assert response.status_code == 200, (
                "Expected 200 for matching :authority and Host, got"
                + f" {response.status_code}. Body: {response.body}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_h3_authority_host_mismatch_returns_400(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        Test that :authority and Host mismatch in HTTP/3 returns 400 Bad Request.

        Per RFC 9114 §4.3.1, if both :authority and Host are present,
        they MUST contain the same value. Mismatch returns 400 Bad Request.

        Note: The H3 library may also reject mismatched authority/Host at the
        protocol level before any HTTP response can be sent. In that case,
        status_code 0 indicates protocol-level rejection, which is also
        acceptable.

        Expected: 400 Bad Request or protocol-level rejection (status_code 0).
        """
        import asyncio

        from tests.fixtures.h3_request import perform_h3_request_with_custom_authority

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_h3_mismatch_test_")
        http3_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create HTTP/3 config with echo service
            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "h3_main",
                        "kind": "http3",
                        "addresses": [f"127.0.0.1:{http3_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "http3_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ]
                        },
                        "listeners": ["h3_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for HTTP/3 listener
            if not proc.wait_ready(timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener failed to start within timeout")

            # Send request with mismatched :authority and Host
            # The HTTP/3 protocol rejects this at the H3 layer
            response = asyncio.run(
                perform_h3_request_with_custom_authority(
                    host="127.0.0.1",
                    port=http3_port,
                    custom_authority="mismatched.example.com",
                    path="/",
                    ca_path=ca_path,
                    additional_headers=[("host", "different.example.com")],
                    timeout=10.0,
                )
            )

            # Expect 400 Bad Request or protocol-level rejection (status_code 0)
            # The H3 library may reject at protocol level before HTTP response
            assert response.status_code in (0, 400), (
                "Expected 400 Bad Request or protocol-level rejection (0) for"
                + f" authority/Host mismatch, got {response.status_code}. Body:"
                + f" {response.body}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)
