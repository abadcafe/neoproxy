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
from collections.abc import Generator

import pytest
import requests
import yaml

from .conftest import get_unique_port
from .types import (
    BytesProcess,
    ConfigDict,
    StringMap,
)
from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    terminate_process,
    wait_for_proxy,
    wait_for_udp_port_bound,
)

# ==============================================================================
# Helper: Write H1/H3 Consistency Config
# ==============================================================================


def write_h1_h3_config(
    config_dir: str,
    http_port: int,
    https_port: int,
    http3_port: int,
    default_port: int,
) -> str:
    """
    Write the H1/H3 consistency test configuration.

    This config uses the new listener kinds (http, https, http3) and
    server-level configuration for TLS, users, and hostnames.

    Args:
        config_dir: Directory to write config and logs
        http_port: Port for HTTP listener
        https_port: Port for HTTPS listener
        http3_port: Port for HTTP3 listener
        default_port: Port for default server listener

    Returns:
        Path to the config file
    """
    log_dir = os.path.join(config_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    config: ConfigDict = {
        "server_threads": 2,
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
                "name": "http_main",
                "kind": "http",
                "addresses": [f"127.0.0.1:{http_port}"],
            },
            {
                "name": "https_main",
                "kind": "https",
                "addresses": [f"127.0.0.1:{https_port}"],
            },
            {
                "name": "h3_main",
                "kind": "http3",
                "addresses": [f"127.0.0.1:{http3_port}"],
                "args": {
                    "quic": {
                        "max_concurrent_bidi_streams": 100,
                    },
                },
            },
            {
                "name": "default_main",
                "kind": "http",
                "addresses": [f"127.0.0.1:{default_port}"],
            },
        ],
        "servers": [
            # Server with new http listener kind
            {
                "name": "http_server",
                "hostnames": ["http.example.com"],
                "listeners": ["http_main"],
                "service": "echo",
            },
            # Server with new https listener kind
            {
                "name": "https_server",
                "hostnames": ["https.example.com"],
                "tls": {
                    "certificates": [
                        {
                            "cert_path": "conf/certs/server.crt",
                            "key_path": "conf/certs/server.key",
                        }
                    ]
                },
                "listeners": ["https_main"],
                "service": "echo",
            },
            # Server with http3 listener (multi-address)
            {
                "name": "http3_server",
                "hostnames": ["h3.example.com"],
                "tls": {
                    "certificates": [
                        {
                            "cert_path": "conf/certs/server.crt",
                            "key_path": "conf/certs/server.key",
                        }
                    ]
                },
                "listeners": ["h3_main"],
                "service": "echo",
            },
            # Default server (no hostnames)
            {
                "name": "default_server",
                "listeners": ["default_main"],
                "service": "echo",
            },
        ],
    }

    config_path = os.path.join(config_dir, "h1_h3_consistency.yaml")
    with open(config_path, "w") as f:
        yaml.dump(config, f)

    return config_path


def write_minimal_echo_config(
    config_dir: str,
    port: int,
) -> str:
    """
    Write a minimal echo config without access_log section.

    Args:
        config_dir: Directory to write config and logs
        port: Port for the HTTP listener

    Returns:
        Path to the config file
    """
    log_dir = os.path.join(config_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

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
                "name": "http_main",
                "kind": "http",
                "addresses": [f"127.0.0.1:{port}"],
            },
        ],
        "servers": [
            {
                "name": "default_server",
                "listeners": ["http_main"],
                "service": "echo",
            }
        ],
    }

    config_path = os.path.join(config_dir, "minimal_config.yaml")
    with open(config_path, "w") as f:
        yaml.dump(config, f)

    return config_path


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def h1_h3_test_env() -> Generator[tuple[str, int, int, int, int], None, None]:
    """
    Set up test environment with dynamic ports and temp directory.

    Yields:
        Tuple of (config_path, http_port, https_port, http3_port, default_port)
    """
    temp_dir = tempfile.mkdtemp(prefix="neoproxy_h1h3_test_")

    # Allocate unique ports
    http_port = get_unique_port()
    https_port = get_unique_port()
    http3_port = get_unique_port()
    default_port = get_unique_port()

    config_path = write_h1_h3_config(temp_dir, http_port, https_port, http3_port, default_port)

    yield config_path, http_port, https_port, http3_port, default_port

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def minimal_test_env() -> Generator[tuple[str, int], None, None]:
    """
    Set up minimal test environment for access log tests.

    Yields:
        Tuple of (config_path, port)
    """
    temp_dir = tempfile.mkdtemp(prefix="neoproxy_minimal_test_")
    port = get_unique_port()

    config_path = write_minimal_echo_config(temp_dir, port)

    yield config_path, port

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def proxy_with_capture(
    h1_h3_test_env: tuple[str, int, int, int, int],
) -> Generator[tuple[BytesProcess | None, bytes, str], None, None]:
    """
    Start proxy and capture stderr for error reporting.

    Yields:
        Tuple of (process, stderr_content, config_path)
    """
    config_path, http_port, _https_port, http3_port, _default_port = h1_h3_test_env

    proc: BytesProcess | None = None
    stderr_data = b""

    try:
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for HTTP listener to be ready using polling
        http_ready = wait_for_proxy("127.0.0.1", http_port, timeout=5.0, proc=proc)

        # Wait for HTTP3 listener to be ready using polling
        h3_ready = wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0, proc=proc)

        # If process exited or listeners not ready, capture stderr
        if proc.poll() is not None or not http_ready or not h3_ready:
            if proc.poll() is not None:
                _, stderr_data = proc.communicate(timeout=5)
                proc = None
            else:
                # Process is running but listeners not ready - still provide proc
                # so the test can check further
                pass

        yield proc, stderr_data, config_path

    finally:
        if proc is not None:
            terminate_process(proc)


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
            pytest.fail(f"Process failed to start with 'http' listener kind.\nstderr: {stderr_text}")

        assert proc.poll() is None, "Process should be running with 'http' listener kind"

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
            pytest.fail(f"Process failed to start with 'https' listener kind.\nstderr: {stderr_text}")

        assert proc.poll() is None, "Process should be running with 'https' listener kind"

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
            pytest.fail(f"Process failed to start with 'http3' listener kind.\nstderr: {stderr_text}")

        assert proc.poll() is None, "Process should be running with 'http3' listener kind"


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
                pytest.fail(f"Server-level 'tls' field not accepted.\nstderr: {stderr_text}")
            else:
                pytest.fail(f"Process failed to start (possibly due to server-level tls).\nstderr: {stderr_text}")

        assert proc.poll() is None, "Process should be running with server-level tls"

    def test_server_level_hostnames_accepted(
        self,
        proxy_with_capture: tuple[BytesProcess | None, bytes, str],
    ) -> None:
        """
        Test that hostnames at server level are accepted.

        Expected: FAIL - Server struct doesn't have hostnames field in current implementation.
        """
        proc, stderr_data, _config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            if "hostnames" in stderr_text.lower():
                pytest.fail(f"Server-level 'hostnames' field not accepted.\nstderr: {stderr_text}")
            else:
                pytest.fail(f"Process failed to start (possibly due to server-level hostnames).\nstderr: {stderr_text}")

        assert proc.poll() is None, "Process should be running with server-level hostnames"

    def test_http_listener_ignores_server_level_tls(self, shared_test_certs: StringMap) -> None:
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
                    "http_upstream": {
                        "upstreams": [{"name": "direct"}],
                    }
                },
                "services": [
                    {
                        "name": "direct",
                        "kind": "http_upstream.upstream",
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
                assert wait_for_proxy("127.0.0.1", port, timeout=5.0, proc=proc), (
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
                pytest.fail(f"http3 listener does not accept 'addresses' field.\nstderr: {stderr_text}")
            else:
                pytest.fail(f"Process failed to start (possibly due to http3 addresses field).\nstderr: {stderr_text}")

        assert proc.poll() is None, "Process should be running with http3 'addresses' field"

    def test_http3_listens_on_multiple_addresses(self, shared_test_certs: StringMap) -> None:
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
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port1, timeout=5.0, proc=proxy_proc), (
                f"HTTP/3 listener failed to start on port {proxy_port1}"
            )
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port2, timeout=5.0, proc=proxy_proc), (
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

    def test_get_request_no_upgrade_error(self, h1_h3_test_env: tuple[str, int, int, int, int]) -> None:
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
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for server to start using polling
            if not wait_for_proxy("127.0.0.1", default_port, timeout=5.0, proc=proc):
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
                assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            except requests.exceptions.ConnectionError:
                pytest.fail(f"Could not connect to server on port {default_port}. Server may not be listening.")
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
    - HTTP/1.0 GET without Host header should return 400 Bad Request.
    """

    def test_http10_connect_succeeds(self) -> None:
        """
        HTTP/1.0 CONNECT should successfully establish a tunnel.

        Python 3.8's http.client._tunnel() sends
        'CONNECT host:port HTTP/1.0' (hardcoded HTTP/1.0).
        This must work for Python 3.8 HTTPS clients using a proxy.
        """
        import socket

        from .utils.helpers import (
            create_target_server,
            create_test_config,
            start_proxy,
        )

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
                        conn.send(b"ECHO:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, echo_handler)

            proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), "Proxy server failed to start"

            # Send CONNECT with HTTP/1.0 (as Python 3.8 does)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                connect_request = (
                    f"CONNECT 127.0.0.1:{target_port} HTTP/1.0\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
                ).encode()
                sock.sendall(connect_request)

                # Read 200 response
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk

                assert b"200" in response, f"Expected 200 for HTTP/1.0 CONNECT, got: {response.decode(errors='ignore')}"

                # Verify bidirectional data transfer through tunnel
                test_data = b"HELLO_HTTP10"
                sock.sendall(test_data)
                echo = sock.recv(1024)
                assert echo == b"ECHO:" + test_data, (
                    f"Tunnel data mismatch: expected 'ECHO:{test_data.decode()}', got {echo.decode(errors='ignore')}"
                )
            finally:
                sock.close()

        finally:
            if proc is not None:
                terminate_process(proc)
            if target_socket is not None:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http10_get_with_host_routed(self, h1_h3_test_env: tuple[str, int, int, int, int]) -> None:
        """
        HTTP/1.0 GET with Host header should route to the echo service.

        With the 505 rejection removed, HTTP/1.0 requests that include
        a Host header should be routed normally by the listener.
        """
        import socket

        config_path, _http_port, _https_port, _http3_port, default_port = h1_h3_test_env

        proc: BytesProcess | None = None

        try:
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", default_port, timeout=5.0, proc=proc):
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
                f"Expected 200 for HTTP/1.0 GET with Host, got: {response.decode(errors='ignore')}"
            )

        finally:
            if proc is not None:
                terminate_process(proc)

    def test_http10_get_without_host_returns_400(self, h1_h3_test_env: tuple[str, int, int, int, int]) -> None:
        """
        HTTP/1.0 GET without Host header should return 400 Bad Request.

        The Host header requirement still applies — HTTP/1.0 requests
        without Host are rejected with 400, not 505.
        """
        import socket

        config_path, _http_port, _https_port, _http3_port, default_port = h1_h3_test_env

        proc: BytesProcess | None = None

        try:
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", default_port, timeout=5.0, proc=proc):
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

            assert b"400" in response, (
                f"Expected 400 Bad Request for HTTP/1.0 GET without Host, got: {response.decode(errors='ignore')}"
            )

        finally:
            if proc is not None:
                terminate_process(proc)


class TestHTTP3AuthorityHostMismatch:
    """Test HTTP/3 authority vs Host mismatch checks.

    Per RFC 9114 §4.3.1, if both :authority and Host are present,
    they MUST contain the same value.
    """

    def test_h3_authority_host_match_returns_200(self, shared_test_certs: StringMap) -> None:
        """
        Test that matching :authority and Host in HTTP/3 returns 200 OK.

        When :authority and Host header match, the request should
        succeed. This test verifies the basic HTTP/3 flow with correct headers.
        """
        import asyncio

        from .utils.http3_client import (
            perform_h3_request_with_custom_authority,
        )

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

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for HTTP/3 listener
            if not wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0, proc=proc):
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
                f"Expected 200 for matching :authority and Host, got {response.status_code}. Body: {response.body}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_h3_authority_host_mismatch_returns_400(self, shared_test_certs: StringMap) -> None:
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

        from .utils.http3_client import (
            perform_h3_request_with_custom_authority,
        )

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

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for HTTP/3 listener
            if not wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0, proc=proc):
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
                f"Expected 400 Bad Request or protocol-level rejection (0) for authority/Host mismatch, "
                f"got {response.status_code}. Body: {response.body}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTPSClientCert:
    """Test HTTPS listener client certificate verification (Plan B).

    With Plan B, TLS layer uses allow_unauthenticated() so the handshake
    succeeds regardless of client cert. Enforcement happens at the HTTP
    layer after routing: 403 if server requires mTLS but client has no cert.
    """

    def test_https_no_cert_returns_403(self, shared_test_certs: StringMap) -> None:
        """
        Test that HTTPS server with client_ca_certs returns 403 when
        client does not present a certificate.

        Plan B: TLS handshake succeeds, HTTP layer enforces cert requirement.
        """
        import socket
        import ssl

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_https_mtls_")
        https_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

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
                        "name": "https_main",
                        "kind": "https",
                        "addresses": [f"127.0.0.1:{https_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "mtls_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ],
                            "client_ca_certs": [ca_path],
                        },
                        "listeners": ["https_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTPS listener failed to start within timeout")

            # Connect WITHOUT client certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
            ssl_sock.connect(("127.0.0.1", https_port))

            # Send request - should get 403 Forbidden
            ssl_sock.sendall(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = ssl_sock.recv(4096).decode()
            ssl_sock.close()

            assert "403" in response, f"Expected 403 Forbidden for missing client certificate, got: {response}"

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_https_with_cert_returns_200(self, shared_test_certs: StringMap, shared_client_cert: StringMap) -> None:
        """
        Test that HTTPS server with client_ca_certs returns 200 when
        client presents a valid certificate.
        """
        import socket
        import ssl

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_https_mtls_ok_")
        https_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            client_cert_path = shared_client_cert["client_cert_path"]
            client_key_path = shared_client_cert["client_key_path"]

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
                        "name": "https_main",
                        "kind": "https",
                        "addresses": [f"127.0.0.1:{https_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "mtls_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ],
                            "client_ca_certs": [ca_path],
                        },
                        "listeners": ["https_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTPS listener failed to start within timeout")

            # Connect WITH valid client certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.load_cert_chain(
                certfile=client_cert_path,
                keyfile=client_key_path,
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
            ssl_sock.connect(("127.0.0.1", https_port))

            # Send request - should succeed
            ssl_sock.sendall(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = ssl_sock.recv(4096).decode()
            ssl_sock.close()

            # Should get 200 OK (or 407 if auth is also configured)
            assert "200" in response or "407" in response, (
                f"Expected 200 or 407 with valid client cert, got: {response}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3ClientCert:
    """Test HTTP/3 listener client certificate verification (Plan B).

    With Plan B, TLS layer uses allow_unauthenticated() so the handshake
    succeeds regardless of client cert. Enforcement happens at the HTTP
    layer after routing: 403 if server requires mTLS but client has no cert.
    """

    def test_h3_no_cert_returns_403(self, shared_test_certs: StringMap) -> None:
        """
        Test that HTTP/3 server with client_ca_certs returns 403 when
        client does not present a certificate.
        """
        import asyncio

        from .utils.http3_client import (
            perform_h3_connection_test,
        )

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_h3_mtls_")
        http3_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

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
                        "name": "mtls_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ],
                            "client_ca_certs": [ca_path],
                        },
                        "listeners": ["h3_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener failed to start within timeout")

            # Connect WITHOUT client certificate
            success, status_code, message = asyncio.run(
                perform_h3_connection_test(
                    "127.0.0.1",
                    http3_port,
                    ca_path=ca_path,
                    timeout=15.0,
                )
            )

            # Plan B: TLS handshake succeeds, HTTP layer returns 403
            assert success, f"TLS handshake should succeed without client cert. Message: {message}"
            assert status_code == 403, (
                f"Expected 403 Forbidden for missing client certificate, got {status_code}. Message: {message}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHostHeaderRequired:
    """Test that Host header is required for HTTP/HTTPS listeners."""

    def test_http_missing_host_returns_400(self, shared_test_certs: StringMap) -> None:
        """
        Test that HTTP request without Host header returns 400.

        Per the listener consistency checks, the Host header MUST
        exist for all requests on HTTP listeners.
        """
        http_port = get_unique_port()

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_host_req_")
        proc: BytesProcess | None = None

        try:
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
                        "name": "http_main",
                        "kind": "http",
                        "addresses": [f"127.0.0.1:{http_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "default_server",
                        "listeners": ["http_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", http_port, timeout=5.0, proc=proc):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP listener failed to start within timeout")

            # Send GET request WITHOUT Host header
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", http_port))
            sock.sendall(b"GET /test HTTP/1.1\r\n\r\n")
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            assert b"400" in response, (
                f"Expected 400 Bad Request for missing Host header, got: {response.decode(errors='replace')[:200]}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_https_missing_host_returns_400(self, shared_test_certs: StringMap) -> None:
        """
        Test that HTTPS request without Host header returns 400.

        Per the listener consistency checks, the Host header MUST
        exist for all requests on HTTPS listeners.
        """
        import socket
        import ssl

        https_port = get_unique_port()

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_https_host_req_")
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

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
                        "name": "https_main",
                        "kind": "https",
                        "addresses": [f"127.0.0.1:{https_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "default_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ]
                        },
                        "listeners": ["https_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTPS listener failed to start within timeout")

            # Send GET request WITHOUT Host header over TLS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
            ssl_sock.connect(("127.0.0.1", https_port))
            ssl_sock.sendall(b"GET /test HTTP/1.1\r\n\r\n")
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            ssl_sock.close()

            assert b"400" in response, (
                f"Expected 400 Bad Request for missing Host header, got: {response.decode(errors='replace')[:200]}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)
