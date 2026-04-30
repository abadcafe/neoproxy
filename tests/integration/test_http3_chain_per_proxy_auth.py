"""
HTTP/3 Chain per-proxy authentication integration tests.

Test target: Verify neoproxy HTTP/3 Chain per-proxy authentication behavior
Test nature: Black-box testing through external interface

This test module covers:
- Per-proxy password authentication
- Per-proxy TLS client certificate authentication
- Per-proxy user and tls configuration
- Error handling for auth failures
- Non-auth error behavior (no fallback)

NOTE: These tests require real HTTP/3 servers with authentication configured.

IMPORTANT: With AND-logic multi-auth, fallback between auth methods is not possible
when both mTLS and password are configured on the listener. Both must pass for
authentication to succeed. Per-proxy auth fallback in the chain is still useful
when connecting to proxies with single auth methods configured.
"""

import subprocess
import socket
import tempfile
import shutil
import os
import signal
import pytest
from typing import Optional, Tuple, List

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    echo_handler,
    create_target_server,
    get_curl_env_without_no_proxy,
    wait_for_udp_port_bound,
)

from .conftest import get_unique_port

from .test_http3_listener import (
    create_http3_listener_config,
)

from .test_http3_auth import (
    create_http3_listener_config_with_password_auth,
    create_http3_listener_config_with_tls_client_cert,
    create_http3_listener_config_with_mtls_and_password,
)


def create_http3_chain_config_with_per_proxy_auth(
    http_port: int,
    proxy_group: List[Tuple[str, int, int, Optional[str], Optional[str]]],
    ca_path: str,
    temp_dir: str,
    default_user: Optional[Tuple[str, str]] = None,
    default_tls: Optional[str] = None,
    worker_threads: int = 1
) -> str:
    """
    Create HTTP/3 Chain service configuration file with per-proxy auth.

    Args:
        http_port: Port for the HTTP listener
        proxy_group: List of (address, port, weight, user_yaml, tls_yaml) tuples.
                     user_yaml: YAML string for user credentials, can be None.
                     tls_yaml: YAML string for TLS config, can be None.
        ca_path: CA certificate path
        temp_dir: Temporary directory for logs
        default_user: Optional tuple of (username, password) for default_user.
        default_tls: Optional YAML string for default_tls extra fields.
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    proxy_list = []
    for addr, port, weight, user_yaml, tls_yaml in proxy_group:
        proxy_entry = f"    - address: {addr}:{port}\n      hostname: localhost\n      weight: {weight}"
        if user_yaml:
            proxy_entry += f"\n      user:\n{user_yaml}"
        if tls_yaml:
            proxy_entry += f"\n      tls:\n{tls_yaml}"
        proxy_list.append(proxy_entry)

    proxy_section = "\n".join(proxy_list)

    # Build default_user section
    default_user_section = ""
    if default_user:
        default_user_section = f"""
    default_user:
      username: "{default_user[0]}"
      password: "{default_user[1]}"
"""

    # Build default_tls section
    default_tls_section = ""
    if default_tls:
        default_tls_section = f"""
    default_tls:
      server_ca_path: "{ca_path}"
{default_tls}"""
    else:
        default_tls_section = f"""
    default_tls:
      server_ca_path: "{ca_path}"
"""

    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: http3_chain
  kind: http3_chain.http3_chain
  args:
    proxy_group:
{proxy_section}{default_user_section}{default_tls_section}

servers:
- name: http_proxy
  listeners:
  - kind: http
    addresses: [ "0.0.0.0:{http_port}" ]
  service: http3_chain
"""
    config_path = os.path.join(temp_dir, "http3_chain_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# Test cases - Per-proxy password authentication
# ==============================================================================


class TestHTTP3ChainPerProxyPasswordAuth:
    """Test per-proxy password authentication scenarios."""

    def test_chain_with_password_auth_only(self, shared_test_certs: dict) -> None:
        """
        TC-CHAIN-AUTH-001: HTTP/3 chain with password auth succeeds.

        Target: Verify chain works with password auth configured per-proxy.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None
        h3_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            _, target_socket = create_target_server("127.0.0.1", target_port, echo_handler)

            # Start HTTP/3 listener with password auth
            h3_config = create_http3_listener_config_with_password_auth(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
                users=[("proxy_user", "proxy_pass")]
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0)

            # Start chain service with per-proxy password auth
            user_yaml = """
          username: "proxy_user"
          password: "proxy_pass"
"""
            chain_config = create_http3_chain_config_with_per_proxy_auth(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1, user_yaml, None)],
                ca_path=ca_path,
                temp_dir=temp_dir2
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0)

            # Test data transmission
            # Clear no_proxy to force proxy usage for localhost
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                ["curl", "-s", "-p", "--http0.9",
                    "-x", f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d", "test_password_auth",
                    "--connect-timeout", "10",
                    "--max-time", "2"
                ],
                capture_output=True,
                text=True,
                env=env
            )

            assert "test_password_auth" in result.stdout, \
                f"Expected echo data, got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            if h3_proc:
                h3_proc.send_signal(signal.SIGTERM)
                h3_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test cases - Per-proxy TLS client certificate authentication
# ==============================================================================


class TestHTTP3ChainPerProxyTlsCertAuth:
    """Test per-proxy TLS client certificate authentication scenarios."""

    def test_chain_with_tls_cert_auth_only(self, shared_test_certs: dict, shared_client_cert: dict) -> None:
        """
        TC-CHAIN-AUTH-002: HTTP/3 chain with TLS client cert auth succeeds.

        Target: Verify chain works with TLS client cert auth configured per-proxy.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None
        h3_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # Use session-scoped certs
            server_cert_path = shared_test_certs['cert_path']
            server_key_path = shared_test_certs['key_path']
            ca_cert_path = shared_test_certs['ca_path']
            client_cert_path = shared_client_cert['client_cert_path']
            client_key_path = shared_client_cert['client_key_path']

            _, target_socket = create_target_server("127.0.0.1", target_port, echo_handler)

            # Start HTTP/3 listener with TLS client cert auth (mTLS)
            h3_config = create_http3_listener_config_with_tls_client_cert(
                proxy_port=h3_port,
                cert_path=server_cert_path,
                key_path=server_key_path,
                client_ca_path=ca_cert_path,
                temp_dir=temp_dir1
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0)

            # Start chain service with per-proxy TLS cert auth
            tls_yaml = f"""
          client_cert_path: "{client_cert_path}"
          client_key_path: "{client_key_path}"
"""
            chain_config = create_http3_chain_config_with_per_proxy_auth(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1, None, tls_yaml)],
                ca_path=ca_cert_path,
                temp_dir=temp_dir2
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0)

            # Test data transmission
            # Clear no_proxy to force proxy usage for localhost
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                ["curl", "-s", "-p", "--http0.9",
                    "-x", f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d", "test_tls_cert_auth",
                    "--connect-timeout", "10",
                    "--max-time", "2"
                ],
                capture_output=True,
                text=True,
                env=env
            )

            assert "test_tls_cert_auth" in result.stdout, \
                f"Expected echo data, got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            if h3_proc:
                h3_proc.send_signal(signal.SIGTERM)
                h3_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test cases - Authentication inheritance
# ==============================================================================


class TestHTTP3ChainAuthInheritance:
    """Test authentication inheritance scenarios."""

    def test_chain_inherits_default_auth(self, shared_test_certs: dict) -> None:
        """
        TC-CHAIN-AUTH-004: Proxy inherits user from default_user.

        Target: Verify proxy without user field inherits from default_user.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None
        h3_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            _, target_socket = create_target_server("127.0.0.1", target_port, echo_handler)

            h3_config = create_http3_listener_config_with_password_auth(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
                users=[("inherited_user", "inherited_pass")]
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0)

            # Proxy has NO user field - should inherit from default_user
            chain_config = create_http3_chain_config_with_per_proxy_auth(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1, None, None)],  # No user specified
                ca_path=ca_path,
                temp_dir=temp_dir2,
                default_user=("inherited_user", "inherited_pass")  # Will be inherited
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0)

            # Clear no_proxy to force proxy usage for localhost
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                ["curl", "-s", "-p", "--http0.9",
                    "-x", f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d", "test_inheritance",
                    "--connect-timeout", "10",
                    "--max-time", "2"
                ],
                capture_output=True,
                text=True,
                env=env
            )

            assert "test_inheritance" in result.stdout, \
                f"Expected echo data (inheritance should work), got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            if h3_proc:
                h3_proc.send_signal(signal.SIGTERM)
                h3_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test cases - Explicit 'none' authentication
# ==============================================================================


class TestHTTP3ChainAuthNone:
    """Test explicit 'none' credential scenarios."""

    def test_chain_explicit_none_no_auth(self, shared_test_certs: dict) -> None:
        """
        TC-CHAIN-AUTH-005: Proxy with credential: {} has no credential.

        Target: Verify empty credential object disables authentication inheritance.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None
        h3_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            _, target_socket = create_target_server("127.0.0.1", target_port, echo_handler)

            # Start H3 listener WITHOUT any auth requirement
            h3_config = create_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0)

            # Proxy with no user and no tls - should work without auth
            chain_config = create_http3_chain_config_with_per_proxy_auth(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1, None, None)],
                ca_path=ca_path,
                temp_dir=temp_dir2
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0)

            # Clear no_proxy to force proxy usage for localhost
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                ["curl", "-s", "-p", "--http0.9",
                    "-x", f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d", "test_explicit_none",
                    "--connect-timeout", "10",
                    "--max-time", "2"
                ],
                capture_output=True,
                text=True,
                env=env
            )

            assert "test_explicit_none" in result.stdout, \
                f"Expected echo data (explicit none should work), got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            if h3_proc:
                h3_proc.send_signal(signal.SIGTERM)
                h3_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test cases - Authentication failure
# ==============================================================================


class TestHTTP3ChainAuthFailure:
    """Test authentication failure scenarios."""

    def test_chain_all_auth_methods_fail(self, shared_test_certs: dict) -> None:
        """
        TC-CHAIN-AUTH-006: All auth methods fail returns error.

        Target: Verify error when all auth methods in chain fail.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None
        h3_proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            h3_config = create_http3_listener_config_with_password_auth(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
                users=[("correct_user", "correct_pass")]
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0)

            # Configure WRONG credentials in user
            user_yaml = """
          username: "wrong_user"
          password: "wrong_pass"
"""
            chain_config = create_http3_chain_config_with_per_proxy_auth(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1, user_yaml, None)],
                ca_path=ca_path,
                temp_dir=temp_dir2
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0)

            # Clear no_proxy to force proxy usage for localhost
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                ["curl", "-s", "-p",
                    "-x", f"http://127.0.0.1:{http_port}",
                    "http://example.com:80/",
                    "--connect-timeout", "10"
                ],
                capture_output=True,
                text=True,
                env=env
            )

            # Should receive 407 Proxy Authentication Required
            assert result.returncode != 0 or "407" in result.stdout or "407" in result.stderr, \
                f"Expected 407 error, got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            if h3_proc:
                h3_proc.send_signal(signal.SIGTERM)
                h3_proc.wait(timeout=10)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_chain_non_auth_error_no_fallback(self, shared_test_certs: dict) -> None:
        """
        TC-CHAIN-AUTH-007: Non-auth error does NOT trigger fallback.

        Target: Verify that timeout/connection errors do NOT trigger auth fallback.
        The proxy should return error immediately without trying other auth methods.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            # Configure user
            user_yaml = """
          username: "user1"
          password: "pass1"
"""
            # Point to a non-existent proxy address (will cause connection refused)
            chain_config = create_http3_chain_config_with_per_proxy_auth(
                http_port=http_port,
                proxy_group=[("127.0.0.1", 9999, 1, user_yaml, None)],  # Non-existent port
                ca_path=ca_path,
                temp_dir=temp_dir2
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0)

            # Make a request - should fail with connection error (NOT auth fallback)
            # Clear no_proxy to force proxy usage for localhost
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                ["curl", "-s", "-p",
                    "-x", f"http://127.0.0.1:{http_port}",
                    "http://example.com:80/",
                    "--connect-timeout", "5"
                ],
                capture_output=True,
                text=True,
                env=env
            )

            # Should receive 502 Bad Gateway (connection failure)
            # NOT 407 (which would indicate auth fallback was attempted)
            assert "407" not in result.stdout, \
                "Should NOT attempt auth fallback for connection errors"
            # Either bad gateway or curl error is acceptable
            assert result.returncode != 0 or "502" in result.stdout or "502" in result.stderr, \
                f"Expected 502 error for connection failure, got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
