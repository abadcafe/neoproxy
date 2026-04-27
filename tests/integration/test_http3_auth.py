"""
HTTP/3 Listener authentication integration tests.

Test target: Verify neoproxy HTTP/3 Listener authentication behavior
Test nature: Black-box testing through external interface

This test module covers:
- 7.3 Authentication scenarios (password and TLS client certificate)

NOTE: These tests use real HTTP/3 clients to verify authentication behavior.
Passwords are stored in plaintext format in the configuration.
"""

import subprocess
import socket
import threading
import tempfile
import shutil
import time
import os
import signal
import base64
import asyncio
import pytest
from typing import Optional, Tuple, List

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    terminate_process,
    echo_handler,
    wait_for_udp_port_bound,
)

from .test_http3_listener import (
    generate_test_certificates,
    generate_client_certificate,
    create_http3_listener_config,
)

from .conftest import get_unique_port

# Alias for convenience

from .utils.http3_client import (
    AIOQUIC_AVAILABLE,
    H3Client,
    perform_h3_connection_test,
    perform_h3_connect_test,
    perform_h3_tls_client_cert_test,
)


# ==============================================================================
# Password authentication helper functions (NEW config format)
# ==============================================================================


def create_http3_listener_config_with_password_auth(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str,
    users: List[Tuple[str, str]],
    quic_config: Optional[str] = None,
    worker_threads: int = 1
) -> str:
    """
    Create HTTP/3 Listener configuration with password authentication.

    Uses NEW config format with server-level TLS and users.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        temp_dir: Temporary directory for logs
        users: List of (username, plaintext_password) tuples
        quic_config: Optional QUIC config YAML string
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    user_lines = []
    for username, password in users:
        user_lines.append(f'      - username: "{username}"')
        user_lines.append(f'        password: "{password}"')

    users_section = "\n".join(user_lines)

    quic_section = ""
    if quic_config:
        quic_section = f"""
      quic:
{quic_config}"""

    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  users:
{users_section}
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]{quic_section}
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "http3_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_listener_config_with_tls_client_cert(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    client_ca_path: str,
    temp_dir: str,
    quic_config: Optional[str] = None,
    worker_threads: int = 1
) -> str:
    """
    Create HTTP/3 Listener configuration with TLS client certificate auth.

    Uses NEW config format with server-level TLS including client_ca_certs.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        client_ca_path: Client CA certificate path
        temp_dir: Temporary directory for logs
        quic_config: Optional QUIC config YAML string
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    quic_section = ""
    if quic_config:
        quic_section = f"""
      quic:
{quic_config}"""

    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
    client_ca_certs:
    - "{client_ca_path}"
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]{quic_section}
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "http3_tls_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_listener_config_with_mtls_and_password(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    client_ca_path: str,
    temp_dir: str,
    users: List[Tuple[str, str]],
    quic_config: Optional[str] = None,
    worker_threads: int = 1
) -> str:
    """
    Create HTTP/3 Listener configuration with BOTH TLS client cert AND password auth.

    Uses NEW config format with server-level TLS and users.

    This is used for testing dual-auth scenarios where BOTH mTLS and password
    must succeed. Transport layer (TLS client cert) is verified first,
    then application layer (password). Both must pass.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        client_ca_path: Client CA certificate path for mTLS
        temp_dir: Temporary directory for logs
        users: List of (username, plaintext_password) tuples for password auth
        quic_config: Optional QUIC config YAML string
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    user_lines = []
    for username, password in users:
        user_lines.append(f'      - username: "{username}"')
        user_lines.append(f'        password: "{password}"')

    users_section = "\n".join(user_lines)

    quic_section = ""
    if quic_config:
        quic_section = f"""
      quic:
{quic_config}"""

    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
    client_ca_certs:
    - "{client_ca_path}"
  users:
{users_section}
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]{quic_section}
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "http3_mtls_password_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# Test cases - 7.3 Password Authentication scenarios
# ==============================================================================


class TestHTTP3PasswordAuth:
    """Test 7.3: HTTP/3 password authentication scenarios."""

    def test_password_auth_config_starts(self) -> None:
        """
        TC-H3-AUTH-002: HTTP/3 listener with password auth starts successfully.

        Target: Verify HTTP/3 listener starts with password authentication config
        using plaintext passwords.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            config_path = create_http3_listener_config_with_password_auth(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[
                    ("testuser", "test_password"),
                ]
            )

            proxy_proc = start_proxy(config_path)

            # Verify process starts and stays running
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start with password auth"

            assert proxy_proc.poll() is None, \
                "HTTP/3 listener should be running with password auth config"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_auth_valid_credentials(self) -> None:
        """
        TC-H3-AUTH-003: Password auth - valid credentials accepted.

        Target: Verify HTTP/3 listener accepts connection with valid credentials.
        Uses real HTTP/3 client to verify authentication.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            # Use plaintext password
            password = "valid_password_123"

            config_path = create_http3_listener_config_with_password_auth(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[
                    ("validuser", password),
                ]
            )

            # Create target server
            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.send(b"ECHO:" + data)
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            # Wait for target server to be ready
            time.sleep(0.5)

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Test with real HTTP/3 client using valid credentials
            async def do_auth_connect():
                success, status_code, message = await perform_h3_connect_test(
                    "127.0.0.1", proxy_port,
                    "127.0.0.1", target_port,
                    ca_path=ca_path,
                    username="validuser",
                    password=password,
                    timeout=15.0
                )
                return success, status_code

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code = loop.run_until_complete(do_auth_connect())
            finally:
                loop.close()

            assert success, "CONNECT with valid credentials should succeed"
            assert status_code == 200, \
                f"Expected 200 with valid credentials, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_auth_invalid_credentials_returns_407(self) -> None:
        """
        TC-H3-AUTH-004: Password auth - invalid credentials return 407.

        Target: Verify HTTP/3 listener returns 407 for invalid credentials.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            # Use plaintext password
            correct_password = "correct_password"

            config_path = create_http3_listener_config_with_password_auth(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[
                    ("testuser", correct_password),
                ]
            )

            # Create target server
            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.send(b"ECHO:" + data)
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            # Wait for target server to be ready
            time.sleep(0.5)

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Test with wrong password
            async def do_auth_connect():
                success, status_code, message = await perform_h3_connect_test(
                    "127.0.0.1", proxy_port,
                    "127.0.0.1", target_port,
                    ca_path=ca_path,
                    username="testuser",
                    password="wrong_password",  # Wrong password
                    timeout=15.0
                )
                return success, status_code

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code = loop.run_until_complete(do_auth_connect())
            finally:
                loop.close()

            # Should get 407 Proxy Authentication Required
            assert status_code == 407, \
                f"Expected 407 for invalid credentials, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_auth_empty_credentials_rejected(self) -> None:
        """
        TC-H3-AUTH-005: Password auth - empty credentials cause startup failure.

        Target: Verify HTTP/3 listener fails to start with empty credentials list.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            # NEW config format: server-level TLS with empty users
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  users: []
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "empty_creds.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )

            try:
                return_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return_code = -1

            # Should exit with error code due to empty credentials
            assert return_code != 0, \
                f"Expected non-zero exit code for empty credentials, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.3 TLS Client Certificate Authentication scenarios
# ==============================================================================


class TestHTTP3TLSClientCertAuth:
    """Test 7.3: HTTP/3 TLS client certificate authentication scenarios."""

    def test_tls_client_cert_auth_config_starts(self) -> None:
        """
        TC-H3-AUTH-006: HTTP/3 listener with TLS client cert auth starts.

        Target: Verify HTTP/3 listener starts with TLS client cert auth config
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            config_path = create_http3_listener_config_with_tls_client_cert(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start with TLS client cert auth"

            assert proxy_proc.poll() is None, \
                "HTTP/3 listener should be running with TLS client cert auth"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tls_client_cert_missing_ca_rejected(self) -> None:
        """
        TC-H3-AUTH-007: TLS client cert auth - missing CA causes startup failure.

        Target: Verify HTTP/3 listener fails to start when client CA file
        is specified but does not exist.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            # NEW config format: server-level TLS with non-existent client_ca_certs
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
    client_ca_certs:
    - "/nonexistent/ca.pem"
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "missing_ca.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )

            try:
                return_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return_code = -1

            # Should exit with error code due to missing CA file
            assert return_code != 0, \
                f"Expected non-zero exit code for missing CA, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tls_client_cert_valid_config(self) -> None:
        """
        TC-H3-AUTH-008: TLS client cert auth - valid configuration.

        Target: Verify HTTP/3 listener correctly configures TLS client cert auth.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            config_path = create_http3_listener_config_with_tls_client_cert(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Verify graceful shutdown works with TLS client cert auth
            proxy_proc.send_signal(signal.SIGTERM)
            return_code = proxy_proc.wait(timeout=10)

            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tls_client_cert_valid_cert_accepted(self) -> None:
        """
        TC-H3-AUTH-009: TLS client cert auth - valid certificate accepted.

        Target: Verify HTTP/3 listener accepts connection with valid client cert.
        Uses real HTTP/3 client with client certificate.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Generate server certificates
            cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

            # Generate client certificate signed by the CA
            client_cert_path, client_key_path = generate_client_certificate(
                temp_dir, ca_path, ca_key_path
            )

            config_path = create_http3_listener_config_with_tls_client_cert(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Test with real HTTP/3 client using valid client certificate
            async def do_client_cert_connect():
                success, message = await perform_h3_tls_client_cert_test(
                    "127.0.0.1", proxy_port,
                    ca_path=ca_path,
                    client_cert_path=client_cert_path,
                    client_key_path=client_key_path,
                    timeout=15.0
                )
                return success, message

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, message = loop.run_until_complete(do_client_cert_connect())
            finally:
                loop.close()

            assert success, f"Connection with valid client cert should succeed: {message}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tls_client_cert_invalid_cert_rejected(self) -> None:
        """
        TC-H3-AUTH-010: TLS client cert auth - invalid certificate handling.

        Target: Test HTTP/3 listener behavior with invalid client certificate.
        Per design section 5.3.2, when TLS client cert auth is configured,
        invalid certificates (not signed by trusted CA) should cause TLS
        handshake failure and the connection must be rejected.

        Expected per design: Connection should be rejected (handshake failure)
        Verification: success must be False, indicating connection was rejected.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Generate server certificates
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            # Generate a different CA and client cert (not signed by server's CA)
            other_ca_cert_path = os.path.join(temp_dir, "other_ca.crt")
            other_ca_key_path = os.path.join(temp_dir, "other_ca.key")
            subprocess.run(
                ["openssl", "genrsa", "-out", other_ca_key_path, "2048"],
                check=True,
                capture_output=True
            )
            subprocess.run(
                [
                    "openssl", "req", "-new", "-x509",
                    "-key", other_ca_key_path,
                    "-out", other_ca_cert_path,
                    "-days", "1",
                    "-subj", "/CN=OtherCA"
                ],
                check=True,
                capture_output=True
            )

            # Generate client cert signed by the OTHER CA (invalid for this server)
            invalid_client_cert_path, invalid_client_key_path = generate_client_certificate(
                temp_dir, other_ca_cert_path, other_ca_key_path
            )

            config_path = create_http3_listener_config_with_tls_client_cert(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,  # Server expects certs signed by this CA
                temp_dir=temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Test with HTTP/3 client using INVALID client certificate
            async def do_invalid_client_cert_connect():
                success, message = await perform_h3_tls_client_cert_test(
                    "127.0.0.1", proxy_port,
                    ca_path=ca_path,
                    client_cert_path=invalid_client_cert_path,
                    client_key_path=invalid_client_key_path,
                    timeout=15.0
                )
                return success, message

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, message = loop.run_until_complete(do_invalid_client_cert_connect())
            finally:
                loop.close()

            # CRITICAL ASSERTION: Per design section 5.3.2, invalid client certificates
            # must be rejected during TLS handshake. The connection must fail.
            # success=True indicates a security vulnerability (invalid cert accepted).
            assert not success, \
                f"SECURITY VIOLATION: Connection with invalid client cert should be rejected. " \
                f"Server accepted invalid certificate signed by untrusted CA. Message: {message}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tls_client_cert_no_cert_rejected(self) -> None:
        """
        TC-H3-AUTH-011: TLS client cert auth - no certificate handling.

        Target: Test HTTP/3 listener behavior when client certificate is not provided.
        Per design section 5.3.2, when TLS client cert auth is configured,
        clients must present a valid certificate. Clients without a certificate
        must be rejected during TLS handshake.

        Expected per design: Connection should be rejected (handshake failure)
        Verification: success must be False, indicating connection was rejected.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Generate server certificates
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            config_path = create_http3_listener_config_with_tls_client_cert(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Test with HTTP/3 client without client certificate
            async def do_no_cert_connect():
                success, message = await perform_h3_connection_test(
                    "127.0.0.1", proxy_port,
                    ca_path=ca_path,
                    timeout=15.0
                )
                return success, message

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, message = loop.run_until_complete(do_no_cert_connect())
            finally:
                loop.close()

            # CRITICAL ASSERTION: Per design section 5.3.2, when TLS client cert auth
            # is configured, clients MUST present a valid certificate. Missing client
            # certificate must cause TLS handshake failure and connection rejection.
            # success=True indicates a security vulnerability (no cert accepted).
            assert not success, \
                f"SECURITY VIOLATION: Connection without client cert should be rejected. " \
                f"Server accepted connection without required client certificate. Message: {message}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.3 Dual Authentication (TLS client cert AND password)
# ==============================================================================


class TestHTTP3DualAuth:
    """Test dual authentication: TLS client cert AND password (AND logic).

    When both tls_client_cert and password auth are configured,
    BOTH must pass. Transport layer (cert) is checked first,
    then application layer (password).
    """

    def test_dual_auth_valid_cert_valid_password_accepted(self) -> None:
        """
        TC-H3-DUAL-001: Both valid cert and valid password -> accepted.

        Target: When both auth methods configured, client with valid cert
        AND valid password should get 200.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)
            client_cert_path, client_key_path = generate_client_certificate(
                temp_dir, ca_path, ca_key_path
            )

            password = "dual_auth_pass"
            config_path = create_http3_listener_config_with_mtls_and_password(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir,
                users=[("dualuser", password)],
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )
            time.sleep(0.5)

            proxy_proc = start_proxy(config_path)
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Use H3Client with client cert AND password
            async def do_dual_auth():
                client = H3Client(
                    "127.0.0.1", proxy_port,
                    ca_path=ca_path,
                    cert_path=client_cert_path,
                    key_path=client_key_path,
                )
                connected = await client.connect()
                if not connected:
                    return False, 0
                try:
                    resp = await client.send_connect_request(
                        "127.0.0.1", target_port,
                        username="dualuser",
                        password=password,
                    )
                    return True, resp.status_code
                finally:
                    await client.close()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                connected, status_code = loop.run_until_complete(do_dual_auth())
            finally:
                loop.close()

            assert connected, "Should connect with valid client cert"
            assert status_code == 200, \
                f"Expected 200 with valid cert + valid password, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_dual_auth_no_cert_with_password_rejected(self) -> None:
        """
        TC-H3-DUAL-002: No client cert but valid password -> rejected at transport.

        Target: When both auth methods configured, client WITHOUT cert
        should be rejected at TLS level (connection fails), even if
        password would be valid. This is the key AND-logic test.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

            password = "dual_auth_pass"
            config_path = create_http3_listener_config_with_mtls_and_password(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir,
                users=[("dualuser", password)],
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )
            time.sleep(0.5)

            proxy_proc = start_proxy(config_path)
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Connect WITHOUT client cert - should fail at transport layer
            async def do_no_cert_connect():
                success, status_code, message = await perform_h3_connect_test(
                    "127.0.0.1", proxy_port,
                    "127.0.0.1", target_port,
                    ca_path=ca_path,
                    username="dualuser",
                    password=password,
                    timeout=15.0,
                )
                return success, status_code, message

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, message = loop.run_until_complete(do_no_cert_connect())
            finally:
                loop.close()

            # CRITICAL: With AND logic, missing cert = transport failure = connection rejected
            # The client should NOT be able to fall back to password auth
            assert not success, \
                f"SECURITY: No cert should be rejected at transport layer even with valid password. " \
                f"Got success={success}, status={status_code}, msg={message}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_dual_auth_valid_cert_wrong_password_returns_407(self) -> None:
        """
        TC-H3-DUAL-003: Valid cert but wrong password -> 407.

        Target: When both auth methods configured, client with valid cert
        passes transport layer, but wrong password fails application layer
        and gets 407.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)
            client_cert_path, client_key_path = generate_client_certificate(
                temp_dir, ca_path, ca_key_path
            )

            config_path = create_http3_listener_config_with_mtls_and_password(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir,
                users=[("dualuser", "correct_password")],
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )
            time.sleep(0.5)

            proxy_proc = start_proxy(config_path)
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Use H3Client with valid client cert but WRONG password
            async def do_wrong_password():
                client = H3Client(
                    "127.0.0.1", proxy_port,
                    ca_path=ca_path,
                    cert_path=client_cert_path,
                    key_path=client_key_path,
                )
                connected = await client.connect()
                if not connected:
                    return False, 0
                try:
                    resp = await client.send_connect_request(
                        "127.0.0.1", target_port,
                        username="dualuser",
                        password="wrong_password",
                    )
                    return True, resp.status_code
                finally:
                    await client.close()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                connected, status_code = loop.run_until_complete(do_wrong_password())
            finally:
                loop.close()

            assert connected, "Should connect with valid client cert (transport passes)"
            assert status_code == 407, \
                f"Expected 407 for valid cert + wrong password, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_dual_auth_valid_cert_no_password_returns_407(self) -> None:
        """
        TC-H3-DUAL-004: Valid cert but no password header -> 407.

        Target: When both auth methods configured, client with valid cert
        passes transport layer, but missing Proxy-Authorization header
        fails application layer and gets 407.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)
            client_cert_path, client_key_path = generate_client_certificate(
                temp_dir, ca_path, ca_key_path
            )

            config_path = create_http3_listener_config_with_mtls_and_password(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir,
                users=[("dualuser", "some_password")],
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )
            time.sleep(0.5)

            proxy_proc = start_proxy(config_path)
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Use H3Client with valid client cert but NO password
            async def do_no_password():
                client = H3Client(
                    "127.0.0.1", proxy_port,
                    ca_path=ca_path,
                    cert_path=client_cert_path,
                    key_path=client_key_path,
                )
                connected = await client.connect()
                if not connected:
                    return False, 0
                try:
                    # Send CONNECT without username/password
                    resp = await client.send_connect_request(
                        "127.0.0.1", target_port,
                    )
                    return True, resp.status_code
                finally:
                    await client.close()

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                connected, status_code = loop.run_until_complete(do_no_password())
            finally:
                loop.close()

            assert connected, "Should connect with valid client cert (transport passes)"
            assert status_code == 407, \
                f"Expected 407 for valid cert + no password, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_dual_auth_invalid_cert_rejected_at_transport(self) -> None:
        """
        TC-H3-DUAL-005: Invalid cert -> rejected at transport (no password fallback).

        Target: When both auth methods configured, client with invalid cert
        (signed by wrong CA) should be rejected at TLS level. No fallback
        to password auth.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

            # Generate a DIFFERENT CA and client cert (not trusted by server)
            other_ca_key_path = os.path.join(temp_dir, "other_ca.key")
            other_ca_cert_path = os.path.join(temp_dir, "other_ca.crt")
            subprocess.run(
                ["openssl", "genrsa", "-out", other_ca_key_path, "2048"],
                check=True, capture_output=True
            )
            subprocess.run(
                [
                    "openssl", "req", "-new", "-x509",
                    "-key", other_ca_key_path,
                    "-out", other_ca_cert_path,
                    "-days", "1",
                    "-subj", "/CN=OtherCA"
                ],
                check=True, capture_output=True
            )
            invalid_cert_path, invalid_key_path = generate_client_certificate(
                temp_dir, other_ca_cert_path, other_ca_key_path
            )

            config_path = create_http3_listener_config_with_mtls_and_password(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                client_ca_path=ca_path,
                temp_dir=temp_dir,
                users=[("dualuser", "valid_password")],
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Connect with INVALID cert - should fail at transport
            async def do_invalid_cert():
                success, message = await perform_h3_tls_client_cert_test(
                    "127.0.0.1", proxy_port,
                    ca_path=ca_path,
                    client_cert_path=invalid_cert_path,
                    client_key_path=invalid_key_path,
                    timeout=15.0,
                )
                return success, message

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, message = loop.run_until_complete(do_invalid_cert())
            finally:
                loop.close()

            # CRITICAL: With AND logic, invalid cert = transport failure
            # No fallback to password auth allowed
            assert not success, \
                f"SECURITY: Invalid cert should be rejected at transport layer " \
                f"even in dual-auth mode. No password fallback. Message: {message}"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.7 Configuration validation for authentication
# ==============================================================================


class TestHTTP3AuthConfigValidation:
    """Test 7.7: HTTP/3 authentication configuration validation scenarios."""

    def test_invalid_auth_type_rejected(self) -> None:
        """
        TC-H3-AUTH-CFG-001: Auth config with unknown field causes startup failure.

        Target: Verify HTTP/3 listener fails when listener args contain
        unrecognized fields (auth is no longer at listener level).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            # NEW config format: test that listener-level auth is rejected
            # (auth should be at server level, not listener level)
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]
      auth:
        some_unknown_field: true
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "invalid_auth_type.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )

            try:
                return_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return_code = -1

            assert return_code != 0, \
                f"Expected non-zero exit code for invalid auth type, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_auth_missing_credentials_rejected(self) -> None:
        """
        TC-H3-AUTH-CFG-002: Password auth without credentials causes failure.

        Target: Verify HTTP/3 listener fails when users is specified
        but credentials list is empty
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            # NEW config format: server-level users with empty list
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  users: []
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "missing_creds.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )

            try:
                return_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return_code = -1

            assert return_code != 0, \
                f"Expected non-zero exit code for missing credentials, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tls_client_cert_missing_ca_path_rejected(self) -> None:
        """
        TC-H3-AUTH-CFG-003: TLS client cert auth without CA path causes failure.

        Target: Verify HTTP/3 listener fails when TLS client cert auth is
        specified but client_ca_certs path doesn't exist
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            # NEW config format: server-level TLS with non-existent client_ca_certs
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
    client_ca_certs:
    - "/nonexistent/ca.pem"
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "missing_ca_path.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )

            try:
                return_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return_code = -1

            assert return_code != 0, \
                f"Expected non-zero exit code for missing CA path, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_plaintext_password_accepted_in_config(self) -> None:
        """
        TC-H3-AUTH-CFG-004: Plaintext password is accepted in configuration.

        Target: Verify HTTP/3 listener accepts plaintext password in config.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            config_path = create_http3_listener_config_with_password_auth(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[
                    ("testuser", "password123"),
                ]
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener should start with plaintext password"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_multiple_users_accepted(self) -> None:
        """
        TC-H3-AUTH-CFG-005: Multiple users are accepted in configuration.

        Target: Verify HTTP/3 listener accepts multiple users in config.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

            config_path = create_http3_listener_config_with_password_auth(
                proxy_port=proxy_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[
                    ("user1", "password1"),
                    ("user2", "password2"),
                    ("admin", "adminpass"),
                ]
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener should start with multiple users"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)
