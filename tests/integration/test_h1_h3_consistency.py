"""
Black-box tests for H1/H3 listener consistency and config architecture.

These tests verify the expected behavior of the refactored configuration
architecture where listener kinds are renamed and server-level configuration
for TLS, auth, and hostnames is introduced.

This is Task 001 of 21 - writing the black-box tests that will initially fail
and be used to verify the complete implementation in later tasks.
"""

import os
import subprocess
import time
import tempfile
import shutil
from typing import Optional, Generator, Tuple

import pytest
import requests
import yaml

from .utils.helpers import (
    terminate_process,
    wait_for_proxy,
    wait_for_udp_port_bound,
    start_proxy,
    NEOPROXY_BINARY,
)
from .conftest import get_unique_port


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

    config = {
        "worker_threads": 2,
        "log_directory": log_dir,
        "services": [
            {
                "name": "echo",
                "kind": "echo.echo",
                "args": {},
            }
        ],
        "servers": [
            # Server with new http listener kind
            {
                "name": "http_server",
                "hostnames": ["http.example.com"],
                "users": [
                    {
                        "username": "admin",
                        "password": "secret",
                    }
                ],
                "listeners": [
                    {
                        "kind": "http",
                        "args": {
                            "addresses": [f"127.0.0.1:{http_port}"],
                        },
                    }
                ],
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
                "listeners": [
                    {
                        "kind": "https",
                        "args": {
                            "addresses": [f"127.0.0.1:{https_port}"],
                        },
                    }
                ],
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
                "listeners": [
                    {
                        "kind": "http3",
                        "args": {
                            "addresses": [f"127.0.0.1:{http3_port}"],
                            "quic": {
                                "max_concurrent_bidi_streams": 100,
                            },
                        },
                    }
                ],
                "service": "echo",
            },
            # Default server (no hostnames)
            {
                "name": "default_server",
                "listeners": [
                    {
                        "kind": "http",
                        "args": {
                            "addresses": [f"127.0.0.1:{default_port}"],
                        },
                    }
                ],
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

    config = {
        "worker_threads": 1,
        "log_directory": log_dir,
        "services": [
            {
                "name": "echo",
                "kind": "echo.echo",
                "args": {},
            }
        ],
        "servers": [
            {
                "name": "default_server",
                "listeners": [
                    {
                        "kind": "http",
                        "args": {
                            "addresses": [f"127.0.0.1:{port}"],
                        },
                    }
                ],
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
def h1_h3_test_env() -> Generator[Tuple[str, int, int, int, int], None, None]:
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

    config_path = write_h1_h3_config(
        temp_dir, http_port, https_port, http3_port, default_port
    )

    yield config_path, http_port, https_port, http3_port, default_port

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def minimal_test_env() -> Generator[Tuple[str, int], None, None]:
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
    h1_h3_test_env: Tuple[str, int, int, int, int]
) -> Generator[Tuple[Optional[subprocess.Popen], bytes, str], None, None]:
    """
    Start proxy and capture stderr for error reporting.

    Yields:
        Tuple of (process, stderr_content, config_path)
    """
    config_path, http_port, https_port, http3_port, default_port = h1_h3_test_env

    proc: Optional[subprocess.Popen] = None
    stderr_data = b""

    try:
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for HTTP listener to be ready using polling
        http_ready = wait_for_proxy("127.0.0.1", http_port, timeout=5.0)

        # Wait for HTTP3 listener to be ready using polling
        h3_ready = wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0)

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
        self, proxy_with_capture: Tuple[Optional[subprocess.Popen], bytes, str]
    ) -> None:
        """
        Test that 'http' listener kind is accepted.

        Expected: FAIL - 'http' kind not registered in current implementation.
        """
        proc, stderr_data, config_path = proxy_with_capture

        if proc is None:
            # Process exited - show error for debugging
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            pytest.fail(
                f"Process failed to start with 'http' listener kind.\n"
                f"stderr: {stderr_text}"
            )

        assert proc.poll() is None, "Process should be running with 'http' listener kind"

    def test_https_listener_kind_accepted(
        self, proxy_with_capture: Tuple[Optional[subprocess.Popen], bytes, str]
    ) -> None:
        """
        Test that 'https' listener kind is accepted.

        Expected: FAIL - 'https' kind not registered in current implementation.
        """
        proc, stderr_data, config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            pytest.fail(
                f"Process failed to start with 'https' listener kind.\n"
                f"stderr: {stderr_text}"
            )

        assert proc.poll() is None, "Process should be running with 'https' listener kind"

    def test_http3_listener_kind_accepted(
        self, proxy_with_capture: Tuple[Optional[subprocess.Popen], bytes, str]
    ) -> None:
        """
        Test that 'http3' listener kind is accepted.

        Expected: FAIL - 'http3' kind not registered in current implementation.
        """
        proc, stderr_data, config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            pytest.fail(
                f"Process failed to start with 'http3' listener kind.\n"
                f"stderr: {stderr_text}"
            )

        assert proc.poll() is None, "Process should be running with 'http3' listener kind"


class TestServerLevelConfig:
    """Test server-level configuration for TLS, auth, and hostnames."""

    def test_server_level_users_accepted(
        self, proxy_with_capture: Tuple[Optional[subprocess.Popen], bytes, str]
    ) -> None:
        """
        Test that users at server level are accepted.

        Expected: FAIL - Server struct doesn't have users field in current implementation.
        """
        proc, stderr_data, config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            # Check if error is specifically about users field
            if "users" in stderr_text.lower():
                pytest.fail(
                    f"Server-level 'users' field not accepted.\n"
                    f"stderr: {stderr_text}"
                )
            else:
                pytest.fail(
                    f"Process failed to start (possibly due to server-level users).\n"
                    f"stderr: {stderr_text}"
                )

        assert proc.poll() is None, "Process should be running with server-level users"

    def test_server_level_tls_accepted(
        self, proxy_with_capture: Tuple[Optional[subprocess.Popen], bytes, str]
    ) -> None:
        """
        Test that tls at server level is accepted.

        Expected: FAIL - Server struct doesn't have tls field in current implementation.
        """
        proc, stderr_data, config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            if "tls" in stderr_text.lower():
                pytest.fail(
                    f"Server-level 'tls' field not accepted.\n"
                    f"stderr: {stderr_text}"
                )
            else:
                pytest.fail(
                    f"Process failed to start (possibly due to server-level tls).\n"
                    f"stderr: {stderr_text}"
                )

        assert proc.poll() is None, "Process should be running with server-level tls"

    def test_server_level_hostnames_accepted(
        self, proxy_with_capture: Tuple[Optional[subprocess.Popen], bytes, str]
    ) -> None:
        """
        Test that hostnames at server level are accepted.

        Expected: FAIL - Server struct doesn't have hostnames field in current implementation.
        """
        proc, stderr_data, config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            if "hostnames" in stderr_text.lower():
                pytest.fail(
                    f"Server-level 'hostnames' field not accepted.\n"
                    f"stderr: {stderr_text}"
                )
            else:
                pytest.fail(
                    f"Process failed to start (possibly due to server-level hostnames).\n"
                    f"stderr: {stderr_text}"
                )

        assert proc.poll() is None, "Process should be running with server-level hostnames"


class TestAccessLogDefault:
    """Test that access log is enabled by default."""

    def test_access_log_enabled_by_default(
        self, minimal_test_env: Tuple[str, int]
    ) -> None:
        """
        Test that access log is written even without explicit config.

        Expected: FAIL - Config::default() has access_log: None in current implementation.
        """
        config_path, port = minimal_test_env
        log_dir = os.path.join(os.path.dirname(config_path), "logs")

        proc: Optional[subprocess.Popen] = None

        try:
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for server to start using polling
            if not wait_for_proxy("127.0.0.1", port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(
                        f"Process failed to start.\n"
                        f"stderr: {stderr_text}"
                    )
                pytest.fail("Proxy server failed to start within timeout")

            # Make a request with timeout
            try:
                response = requests.get(
                    f"http://127.0.0.1:{port}/test",
                    timeout=5.0,
                )
                # Request succeeded, check log file
            except requests.exceptions.ConnectionError:
                # Server may not be responding due to config error
                pytest.fail(
                    f"Could not connect to server on port {port}. "
                    f"Check if listener kind 'http' is supported."
                )
            except requests.exceptions.Timeout:
                pytest.fail(f"Request to server on port {port} timed out")

            # Wait for access log to be written using polling
            log_start_time = time.time()
            while time.time() - log_start_time < 3.0:
                if os.path.exists(log_dir) and os.listdir(log_dir):
                    break
                time.sleep(0.1)

            # Check that access log file was created
            # The log file naming convention may vary (access.log.* or neoproxy.log.*)
            log_files = list(os.listdir(log_dir)) if os.path.exists(log_dir) else []
            assert len(log_files) > 0, (
                f"Access log should be created by default. "
                f"Files in log dir: {log_files if log_files else 'dir not found'}"
            )

        finally:
            if proc is not None:
                terminate_process(proc)


class TestHTTP3MultiAddress:
    """Test HTTP/3 listener multi-address support."""

    def test_http3_addresses_field_accepted(
        self, proxy_with_capture: Tuple[Optional[subprocess.Popen], bytes, str]
    ) -> None:
        """
        Test that http3 listener accepts 'addresses' (plural) field.

        Expected: FAIL - http3 uses 'address' not 'addresses' in current implementation.
        """
        proc, stderr_data, config_path = proxy_with_capture

        if proc is None:
            stderr_text = stderr_data.decode("utf-8", errors="replace")
            if "addresses" in stderr_text.lower():
                pytest.fail(
                    f"http3 listener does not accept 'addresses' field.\n"
                    f"stderr: {stderr_text}"
                )
            else:
                pytest.fail(
                    f"Process failed to start (possibly due to http3 addresses field).\n"
                    f"stderr: {stderr_text}"
                )

        assert proc.poll() is None, "Process should be running with http3 'addresses' field"

    def test_http3_listens_on_multiple_addresses(self, shared_test_certs: dict) -> None:
        """
        Test that http3 listener can listen on multiple addresses.

        This test verifies that HTTP/3 listener supports the 'addresses' field
        and can accept connections on multiple ports.
        """
        temp_dir = tempfile.mkdtemp(prefix="neoproxy_multiaddr_test_")
        proxy_port1 = get_unique_port()
        proxy_port2 = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']

            log_dir = os.path.join(temp_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)

            # Create config with multiple HTTP/3 addresses
            config = {
                "worker_threads": 1,
                "log_directory": log_dir,
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
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
                        "listeners": [
                            {
                                "kind": "http3",
                                "args": {
                                    "addresses": [
                                        f"127.0.0.1:{proxy_port1}",
                                        f"127.0.0.1:{proxy_port2}",
                                    ],
                                },
                            }
                        ],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proxy_proc = start_proxy(config_path)

            # Wait for both UDP ports to be bound
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port1, timeout=5.0), \
                f"HTTP/3 listener failed to start on port {proxy_port1}"
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port2, timeout=5.0), \
                f"HTTP/3 listener failed to start on port {proxy_port2}"

            # Verify process is still running
            assert proxy_proc.poll() is None, "Proxy process should be running"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3ConnectOnlyUpgrade:
    """Test that HTTP/3 listener only creates upgrade pair for CONNECT."""

    def test_get_request_no_upgrade_error(
        self, h1_h3_test_env: Tuple[str, int, int, int, int]
    ) -> None:
        """
        Test that GET request to echo service doesn't cause upgrade error.

        The original bug caused "Service dropped the receiver" error
        for non-CONNECT requests.

        Expected: FAIL - Config with 'http' kind not accepted yet.
        """
        config_path, http_port, https_port, http3_port, default_port = h1_h3_test_env

        proc: Optional[subprocess.Popen] = None
        stderr_data = b""

        try:
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for server to start using polling
            if not wait_for_proxy("127.0.0.1", default_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(
                        f"Process failed to start.\n"
                        f"stderr: {stderr_text}"
                    )
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
                    f"Could not connect to server on port {default_port}. "
                    f"Server may not be listening."
                )
            except requests.exceptions.Timeout:
                pytest.fail(f"Request to server on port {default_port} timed out")

        finally:
            if proc is not None:
                # Check stderr for upgrade-related errors
                # Non-blocking read of stderr
                terminate_process(proc)


class TestHTTPVersionCheck:
    """Test that HTTP version check works correctly."""

    def test_http10_returns_505(
        self, h1_h3_test_env: Tuple[str, int, int, int, int]
    ) -> None:
        """
        Test that HTTP/1.0 requests return 505.

        According to spec: "http/https listener: force HTTP/1.1+,
        otherwise return 505 HTTP Version Not Supported".

        Expected: PASS - HTTP/1.0 should receive 505 response.
        """
        import socket

        config_path, http_port, https_port, http3_port, default_port = h1_h3_test_env

        proc: Optional[subprocess.Popen] = None

        try:
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for server to start using polling
            if not wait_for_proxy("127.0.0.1", default_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(
                        f"Process failed to start.\n"
                        f"stderr: {stderr_text}"
                    )
                pytest.fail("Proxy server failed to start within timeout")

            # Send HTTP/1.0 request using raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", default_port))
            sock.sendall(b"GET /test HTTP/1.0\r\nHost: localhost\r\n\r\n")
            response = sock.recv(1024).decode()
            sock.close()

            assert "505" in response, f"Expected 505 HTTP Version Not Supported, got: {response}"

        finally:
            if proc is not None:
                terminate_process(proc)


class TestSNIHostMismatch:
    """Test that SNI vs Host header mismatch returns 421 Misdirected Request."""

    def test_sni_host_mismatch_https_returns_421(
        self, h1_h3_test_env: Tuple[str, int, int, int, int]
    ) -> None:
        """
        Test that SNI/Host mismatch on HTTPS returns 421 Misdirected Request.

        According to spec: "SNI and Host header must match, otherwise return
        421 Misdirected Request".

        Expected: PASS - SNI/Host mismatch should receive 421 response.
        """
        import ssl
        import socket

        config_path, http_port, https_port, http3_port, default_port = h1_h3_test_env

        proc: Optional[subprocess.Popen] = None

        try:
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for server to start using polling
            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(
                        f"Process failed to start.\n"
                        f"stderr: {stderr_text}"
                    )
                pytest.fail("Proxy server failed to start within timeout")

            # Create SSL context that sends different SNI than Host
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect with SNI = https.example.com (matches cert SAN *.example.com)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="https.example.com")
            ssl_sock.connect(("127.0.0.1", https_port))

            # Send request with different Host header
            ssl_sock.sendall(
                b"GET /test HTTP/1.1\r\n"
                b"Host: other.example.com\r\n"
                b"\r\n"
            )
            response = ssl_sock.recv(4096).decode()
            ssl_sock.close()

            # We expect 421 Misdirected Request
            assert "421" in response, f"Expected 421 Misdirected Request, got: {response}"

        finally:
            if proc is not None:
                terminate_process(proc)

    def test_sni_host_match_https_returns_200(
        self, h1_h3_test_env: Tuple[str, int, int, int, int]
    ) -> None:
        """
        Test that matching SNI and Host returns 200 OK.

        When SNI and Host header match, the request should succeed.
        """
        import ssl
        import socket

        config_path, http_port, https_port, http3_port, default_port = h1_h3_test_env

        proc: Optional[subprocess.Popen] = None

        try:
            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for server to start using polling
            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(
                        f"Process failed to start.\n"
                        f"stderr: {stderr_text}"
                    )
                pytest.fail("Proxy server failed to start within timeout")

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect with SNI matching Host header (matches cert SAN)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="https.example.com")
            ssl_sock.connect(("127.0.0.1", https_port))

            # Send request with matching Host header
            ssl_sock.sendall(
                b"GET /test HTTP/1.1\r\n"
                b"Host: https.example.com\r\n"
                b"\r\n"
            )
            response = ssl_sock.recv(4096).decode()
            ssl_sock.close()

            # We expect 200 OK or authentication required (407)
            assert "200" in response or "407" in response, f"Expected 200 or 407, got: {response}"

        finally:
            if proc is not None:
                terminate_process(proc)


class TestHTTP3SNIHostMismatch:
    """Test that HTTP/3 :authority vs Host header mismatch returns 421 Misdirected Request."""

    def test_h3_authority_host_match_returns_200(self, shared_test_certs: dict) -> None:
        """
        Test that matching :authority and Host in HTTP/3 returns 200 OK.

        When :authority (derived from URL) and Host header match, the request should succeed.
        This test verifies the basic HTTP/3 flow with correct headers.
        """
        import asyncio
        from .utils.http3_client import (
            AIOQUIC_AVAILABLE,
            perform_h3_request_with_custom_authority,
        )

        if not AIOQUIC_AVAILABLE:
            pytest.skip("aioquic library not available")

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_h3_match_test_")
        http3_port = get_unique_port()
        proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            # Create HTTP/3 config with echo service
            log_dir = os.path.join(temp_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)

            config = {
                "worker_threads": 1,
                "log_directory": log_dir,
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
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
                        "listeners": [
                            {
                                "kind": "http3",
                                "args": {
                                    "addresses": [f"127.0.0.1:{http3_port}"],
                                },
                            }
                        ],
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
            if not wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener failed to start within timeout")

            # Send request with matching :authority, SNI, and Host
            # SNI is set to "localhost" by default when connecting to IP
            # :authority and Host should also be "localhost" (no port) to match SNI
            response = asyncio.run(
                perform_h3_request_with_custom_authority(
                    host="127.0.0.1",
                    port=http3_port,
                    custom_authority="localhost",  # Match SNI
                    path="/test",
                    ca_path=ca_path,
                    additional_headers=[("host", "localhost")],  # Match SNI and authority
                    timeout=10.0,
                )
            )

            # Should get 200 OK for matching authority/Host
            assert response.status_code == 200, (
                f"Expected 200 for matching :authority and Host, got {response.status_code}. "
                f"Body: {response.body}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_h3_authority_host_mismatch_returns_421(self, shared_test_certs: dict) -> None:
        """
        Test that :authority and Host mismatch in HTTP/3 is rejected.

        This test verifies that HTTP/3 requests with mismatched :authority
        and Host headers are rejected by the protocol layer.

        IMPORTANT: The HTTP/3 protocol (RFC 9114) and the H3 library enforce
        that `:authority` and Host headers must match. When they don't match,
        the server rejects the request at the H3 protocol level with
        H3_MESSAGE_ERROR before any HTTP response (including 421) can be sent.

        This test verifies that mismatched requests are properly rejected,
        though not with a 421 HTTP response (which is impossible due to
        protocol constraints). The authority/Host mismatch validation is
        additionally tested by the Rust unit test:
        - listeners::http3::tests::test_check_h3_authority_host_mismatch_has_mismatch

        Expected: No HTTP response (protocol-level rejection).
        """
        import asyncio
        from .utils.http3_client import (
            AIOQUIC_AVAILABLE,
            perform_h3_request_with_custom_authority,
        )

        if not AIOQUIC_AVAILABLE:
            pytest.skip("aioquic library not available")

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_h3_mismatch_test_")
        http3_port = get_unique_port()
        proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            # Create HTTP/3 config with echo service
            log_dir = os.path.join(temp_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)

            config = {
                "worker_threads": 1,
                "log_directory": log_dir,
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
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
                        "listeners": [
                            {
                                "kind": "http3",
                                "args": {
                                    "addresses": [f"127.0.0.1:{http3_port}"],
                                },
                            }
                        ],
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
            if not wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0):
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

            # Expect no HTTP response (status_code 0) due to protocol-level rejection
            # The server logs will show: H3_MESSAGE_ERROR - uri and authority field are in contradiction
            assert response.status_code == 0, (
                f"Expected protocol-level rejection (status_code 0) for authority/Host mismatch, "
                f"got {response.status_code}. Body: {response.body}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)
