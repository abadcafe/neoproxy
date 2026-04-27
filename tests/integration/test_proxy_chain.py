"""
Proxy chain integration tests.

Test target: Verify complete proxy chain with authentication at each layer.
Test nature: Black-box testing through external interface (curl).

Test matrix:
- HTTP(Password) -> HTTP/3(Password) -> Target
- HTTP(Password) -> HTTP/3(TLS Cert) -> Target
- SOCKS5(Password) -> HTTP/3(Password) -> Target
- SOCKS5(Password) -> HTTP/3(TLS Cert) -> Target
"""

import subprocess
import os
import signal
import time
import tempfile
import shutil
import socket
import threading
from typing import Optional, Tuple

import pytest

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    wait_for_udp_port_bound,
)

from .test_http3_listener import (
    generate_test_certificates,
    generate_client_certificate,
)

# Alias for convenience

from .utils.http_echo import http_echo_handler, read_http_request

from .conftest import get_unique_port


# ==============================================================================
# Configuration helper functions
# ==============================================================================


def create_upstream_password_config(
    h3_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str
) -> str:
    """Create upstream HTTP/3 config with password auth."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: upstream_http3
    users:
      - username: user1
        password: pass1
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
    listeners:
      - kind: http3
        args:
          addresses: ["0.0.0.0:{h3_port}"]
    service: tunnel
"""
    config_path = os.path.join(temp_dir, "upstream_password.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_upstream_tls_cert_config(
    h3_port: int,
    cert_path: str,
    key_path: str,
    client_ca_path: str,
    temp_dir: str
) -> str:
    """Create upstream HTTP/3 config with TLS client cert auth."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: upstream_http3_tls
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
      client_ca_path: "{client_ca_path}"
    listeners:
      - kind: http3
        args:
          addresses: ["0.0.0.0:{h3_port}"]
    service: tunnel
"""
    config_path = os.path.join(temp_dir, "upstream_tls_cert.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_entry_http_password_config(
    http_port: int,
    h3_port: int,
    ca_path: str,
    temp_dir: str
) -> str:
    """Create entry HTTP config with password auth, connecting to password upstream."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{h3_port}"
          hostname: localhost
          weight: 1
          user:
            username: user1
            password: pass1
          tls:
            server_ca_path: "{ca_path}"

servers:
  - name: entry_http
    users:
      - username: user1
        password: pass1
    listeners:
      - kind: http
        args:
          addresses: ["127.0.0.1:{http_port}"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_password.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_entry_http_tls_cert_config(
    http_port: int,
    h3_port: int,
    ca_path: str,
    client_cert_path: str,
    client_key_path: str,
    temp_dir: str
) -> str:
    """Create entry HTTP config with password auth, connecting to TLS cert upstream."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{h3_port}"
          hostname: localhost
          weight: 1
          tls:
            client_cert_path: "{client_cert_path}"
            client_key_path: "{client_key_path}"
            server_ca_path: "{ca_path}"

servers:
  - name: entry_http
    users:
      - username: user1
        password: pass1
    listeners:
      - kind: http
        args:
          addresses: ["127.0.0.1:{http_port}"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_tls_cert.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_entry_socks5_password_config(
    socks5_port: int,
    h3_port: int,
    ca_path: str,
    temp_dir: str
) -> str:
    """Create entry SOCKS5 config with password auth, connecting to password upstream."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{h3_port}"
          hostname: localhost
          weight: 1
          user:
            username: user1
            password: pass1
          tls:
            server_ca_path: "{ca_path}"

servers:
  - name: entry_socks5
    users:
      - username: user1
        password: pass1
    listeners:
      - kind: socks5
        args:
          addresses: ["127.0.0.1:{socks5_port}"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_socks5_password.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_entry_socks5_tls_cert_config(
    socks5_port: int,
    h3_port: int,
    ca_path: str,
    client_cert_path: str,
    client_key_path: str,
    temp_dir: str
) -> str:
    """Create entry SOCKS5 config with password auth, connecting to TLS cert upstream."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{h3_port}"
          hostname: localhost
          weight: 1
          tls:
            client_cert_path: "{client_cert_path}"
            client_key_path: "{client_key_path}"
            server_ca_path: "{ca_path}"

servers:
  - name: entry_socks5
    service: proxy_chain
    listeners:
      - kind: socks5
        args:
          addresses:
            - "127.0.0.1:{socks5_port}"
          auth:
            users:
              - username: user1
                password: pass1
"""
    config_path = os.path.join(temp_dir, "entry_socks5_tls_cert.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# Target Server Helper
# ==============================================================================


def create_echo_target_server(
    host: str,
    port: int
) -> Tuple[threading.Thread, socket.socket]:
    """
    Create an HTTP echo target server for testing.

    This server properly parses HTTP requests and echoes POST body back
    in a valid HTTP 200 response, compatible with curl's HTTP protocol
    expectations (CR-011).

    Args:
        host: Listen address
        port: Listen port

    Returns:
        Tuple[threading.Thread, socket.socket]: Server thread and socket
    """
    return create_target_server(host, port, http_echo_handler)


# ==============================================================================
# Common Test Runner
# ==============================================================================


def run_proxy_chain_test(
    entry_type: str,  # "http" or "socks5"
    upstream_auth: str,  # "password" or "tls_cert"
    target_type: str,  # "baidu" or "mock"
    http_port: int,
    h3_port: int,
    target_port: Optional[int],
    temp_dir1: str,
    temp_dir2: str,
) -> None:
    """
    Run a proxy chain test with the specified configuration.

    This function consolidates the common test logic to reduce code duplication.

    Args:
        entry_type: Entry proxy type ("http" or "socks5")
        upstream_auth: Upstream auth type ("password" or "tls_cert")
        target_type: Target type ("baidu" or "mock")
        http_port: Entry HTTP/SOCKS5 port
        h3_port: Upstream HTTP/3 port
        target_port: Target server port (for mock tests)
        temp_dir1: Temp dir for upstream
        temp_dir2: Temp dir for entry
    """
    upstream_proc: Optional[subprocess.Popen] = None
    entry_proc: Optional[subprocess.Popen] = None
    target_socket: Optional[socket.socket] = None
    target_thread: Optional[threading.Thread] = None

    try:
        cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir1)

        # Generate client certificate for TLS cert auth
        client_cert_path = None
        client_key_path = None
        if upstream_auth == "tls_cert":
            client_cert_path, client_key_path = generate_client_certificate(
                temp_dir1, ca_path, ca_key_path
            )

        # Create upstream config
        if upstream_auth == "password":
            upstream_config = create_upstream_password_config(
                h3_port, cert_path, key_path, temp_dir1
            )
        else:
            upstream_config = create_upstream_tls_cert_config(
                h3_port, cert_path, key_path, ca_path, temp_dir1
            )

        upstream_proc = start_proxy(upstream_config)
        assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
            "Upstream HTTP/3 listener failed to start"

        # Create entry config
        if entry_type == "http":
            if upstream_auth == "password":
                entry_config = create_entry_http_password_config(
                    http_port, h3_port, ca_path, temp_dir2
                )
            else:
                entry_config = create_entry_http_tls_cert_config(
                    http_port, h3_port, ca_path,
                    client_cert_path, client_key_path, temp_dir2
                )
        else:  # socks5
            if upstream_auth == "password":
                entry_config = create_entry_socks5_password_config(
                    http_port, h3_port, ca_path, temp_dir2
                )
            else:
                entry_config = create_entry_socks5_tls_cert_config(
                    http_port, h3_port, ca_path,
                    client_cert_path, client_key_path, temp_dir2
                )

        entry_proc = start_proxy(entry_config)
        assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
            "Entry listener failed to start"

        # Create target server for mock tests
        if target_type == "mock" and target_port:
            target_thread, target_socket = create_echo_target_server(
                "127.0.0.1", target_port
            )

        # Run curl
        if entry_type == "http":
            curl_proxy = f"http://user1:pass1@127.0.0.1:{http_port}"
            curl_cmd = ["curl", "-p", "-x", curl_proxy]
        else:  # socks5
            curl_cmd = [
                "curl", "--socks5-basic", "--socks5-hostname",
                f"127.0.0.1:{http_port}",
                "--proxy-user", "user1:pass1"
            ]

        if target_type == "baidu":
            curl_cmd.extend([
                "https://www.baidu.com", "-s", "-o", "/dev/null",
                "-w", "%{http_code}", "--connect-timeout", "30"
            ])
            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            assert result.stdout == "200", \
                f"Expected 200, got {result.stdout}. stderr: {result.stderr}"
        else:  # mock
            curl_cmd.extend([
                f"http://127.0.0.1:{target_port}",
                "-d", "test_data_chain",
                "--connect-timeout", "5"
            ])
            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            assert "test_data_chain" in result.stdout, \
                f"Expected echo, got stdout: {result.stdout}, stderr: {result.stderr}"

    finally:
        if entry_proc:
            entry_proc.send_signal(signal.SIGTERM)
            entry_proc.wait(timeout=10)
        if upstream_proc:
            upstream_proc.send_signal(signal.SIGTERM)
            upstream_proc.wait(timeout=10)
        if target_socket:
            target_socket.close()
        shutil.rmtree(temp_dir1, ignore_errors=True)
        shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test classes - HTTP(Password) -> HTTP/3(Password) -> Target
# ==============================================================================


class TestProxyChainHTTPToHTTP3Password:
    """HTTP(Password) -> HTTP/3(Password) -> Target"""

    def test_to_baidu(self) -> None:
        """TC-CHAIN-PWD-001: HTTP(password)->HTTP/3(password)->baidu.com."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="password",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )

    def test_to_mock(self) -> None:
        """TC-CHAIN-PWD-002: HTTP(password)->HTTP/3(password)->mock echo."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="password",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )


# ==============================================================================
# Test classes - HTTP(Password) -> HTTP/3(TLS Cert) -> Target
# ==============================================================================


class TestProxyChainHTTPToHTTP3TlsCert:
    """HTTP(Password) -> HTTP/3(TLS Cert) -> Target"""

    def test_to_baidu(self) -> None:
        """TC-CHAIN-TLS-001: HTTP(password)->HTTP/3(TLS cert)->baidu.com."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="tls_cert",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )

    def test_to_mock(self) -> None:
        """TC-CHAIN-TLS-002: HTTP(password)->HTTP/3(TLS cert)->mock echo."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="tls_cert",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )


# ==============================================================================
# Test classes - SOCKS5(Password) -> HTTP/3(Password) -> Target
# ==============================================================================


class TestProxyChainSocks5ToHTTP3Password:
    """SOCKS5(Password) -> HTTP/3(Password) -> Target"""

    def test_to_baidu(self) -> None:
        """TC-CHAIN-S5-PWD-001: SOCKS5(password)->HTTP/3(password)->baidu.com."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="password",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )

    def test_to_mock(self) -> None:
        """TC-CHAIN-S5-PWD-002: SOCKS5(password)->HTTP/3(password)->mock echo."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="password",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )


# ==============================================================================
# Test classes - SOCKS5(Password) -> HTTP/3(TLS Cert) -> Target
# ==============================================================================


class TestProxyChainSocks5ToHTTP3TlsCert:
    """SOCKS5(Password) -> HTTP/3(TLS Cert) -> Target"""

    def test_to_baidu(self) -> None:
        """TC-CHAIN-S5-TLS-001: SOCKS5(password)->HTTP/3(TLS cert)->baidu.com."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="tls_cert",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )

    def test_to_mock(self) -> None:
        """TC-CHAIN-S5-TLS-002: SOCKS5(password)->HTTP/3(TLS cert)->mock echo."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="tls_cert",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
        )


# ==============================================================================
# Negative authentication tests (SR-006)
# ==============================================================================


def create_entry_http_no_upstream_auth_config(
    http_port: int,
    h3_port: int,
    ca_path: str,
    temp_dir: str
) -> str:
    """Create entry HTTP config with password auth, no upstream auth."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{h3_port}"
          hostname: localhost
          weight: 1
      default_tls:
        server_ca_path: "{ca_path}"

servers:
  - name: entry_http
    users:
      - username: user1
        password: pass1
    listeners:
      - kind: http
        args:
          addresses: ["127.0.0.1:{http_port}"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_no_upstream_auth.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_entry_socks5_no_upstream_auth_config(
    socks5_port: int,
    h3_port: int,
    ca_path: str,
    temp_dir: str
) -> str:
    """Create entry SOCKS5 config with password auth, no upstream auth."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{h3_port}"
          hostname: localhost
          weight: 1
      default_tls:
        server_ca_path: "{ca_path}"

servers:
  - name: entry_socks5
    service: proxy_chain
    listeners:
      - kind: socks5
        args:
          addresses:
            - "127.0.0.1:{socks5_port}"
          auth:
            users:
              - username: user1
                password: pass1
"""
    config_path = os.path.join(temp_dir, "entry_socks5_no_upstream_auth.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_entry_http_wrong_upstream_auth_config(
    http_port: int,
    h3_port: int,
    ca_path: str,
    temp_dir: str
) -> str:
    """Create entry HTTP config with password auth, wrong upstream credentials."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{h3_port}"
          hostname: localhost
          weight: 1
          user:
            username: wrong_user
            password: wrong_pass
          tls:
            server_ca_path: "{ca_path}"

servers:
  - name: entry_http
    users:
      - username: user1
        password: pass1
    listeners:
      - kind: http
        args:
          addresses: ["127.0.0.1:{http_port}"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_wrong_upstream_auth.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_upstream_no_auth_config(
    h3_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str
) -> str:
    """Create upstream HTTP/3 config without auth."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: upstream_http3
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
    listeners:
      - kind: http3
        args:
          addresses: ["0.0.0.0:{h3_port}"]
    service: tunnel
"""
    config_path = os.path.join(temp_dir, "upstream_no_auth.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def _is_407_response(result: subprocess.CompletedProcess) -> bool:
    """Check if a curl result indicates a 407 Proxy Authentication Required response.

    For CONNECT tunnels (HTTPS through HTTP proxy), curl exits with code 56
    and reports 'response 407' in stderr, while %{http_code} shows '000'.
    For plain HTTP proxy requests, curl returns HTTP code 407 normally.

    Args:
        result: CompletedProcess from curl subprocess run

    Returns:
        True if the response indicates 407 Proxy Authentication Required
    """
    # Case 1: Plain HTTP proxy request - HTTP status code 407
    if result.stdout.strip() == "407":
        return True
    # Case 2: CONNECT tunnel - curl exit code 56 with "407" in stderr
    if result.returncode == 56 and "407" in result.stderr:
        return True
    return False


class TestNegativeAuthHTTPEntry:
    """Negative tests for HTTP entry proxy authentication."""

    def test_http_entry_missing_auth_returns_407(self) -> None:
        """TC-NEG-AUTH-001: HTTP entry without Proxy-Authorization returns 407.

        When a proxy requires password authentication and the client sends
        a request without Proxy-Authorization header, the proxy must respond
        with 407 Proxy Authentication Required.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: Optional[subprocess.Popen] = None
        entry_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir1)

            # Start upstream HTTP/3 without auth (entry auth is what we test)
            upstream_config = create_upstream_no_auth_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream HTTP/3 listener failed to start"

            # Start entry HTTP with password auth
            entry_config = create_entry_http_no_upstream_auth_config(
                http_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "Entry HTTP listener failed to start"

            time.sleep(0.5)

            # Send CONNECT request without Proxy-Authorization.
            # For HTTPS through HTTP proxy (CONNECT tunnel), curl reports
            # exit code 56 and "response 407" in stderr when proxy returns 407.
            # Note: do NOT use -s flag, otherwise curl suppresses the 407
            # message from stderr.
            result = subprocess.run(
                [
                    "curl", "-x", f"http://127.0.0.1:{http_port}",
                    "https://www.baidu.com", "-o", "/dev/null",
                    "-w", "%{http_code}", "--connect-timeout", "5"
                ],
                capture_output=True, text=True
            )

            assert _is_407_response(result), \
                f"Expected 407 response, got http_code={result.stdout}, " \
                f"returncode={result.returncode}, stderr={result.stderr}"

        finally:
            if entry_proc:
                entry_proc.send_signal(signal.SIGTERM)
                entry_proc.wait(timeout=10)
            if upstream_proc:
                upstream_proc.send_signal(signal.SIGTERM)
                upstream_proc.wait(timeout=10)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_http_entry_wrong_credentials_returns_407(self) -> None:
        """TC-NEG-AUTH-002: HTTP entry with wrong credentials returns 407.

        When a proxy requires password authentication and the client sends
        incorrect credentials in the Proxy-Authorization header, the proxy
        must respond with 407 Proxy Authentication Required.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: Optional[subprocess.Popen] = None
        entry_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir1)

            # Start upstream HTTP/3 without auth (entry auth is what we test)
            upstream_config = create_upstream_no_auth_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream HTTP/3 listener failed to start"

            # Start entry HTTP with password auth
            entry_config = create_entry_http_no_upstream_auth_config(
                http_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "Entry HTTP listener failed to start"

            time.sleep(0.5)

            # Send request with wrong credentials.
            # For CONNECT tunnels, curl reports exit code 56 + "response 407".
            # Note: do NOT use -s flag, otherwise curl suppresses the 407
            # message from stderr.
            result = subprocess.run(
                [
                    "curl", "-x", f"http://wrong_user:wrong_pass@127.0.0.1:{http_port}",
                    "https://www.baidu.com", "-o", "/dev/null",
                    "-w", "%{http_code}", "--connect-timeout", "5"
                ],
                capture_output=True, text=True
            )

            assert _is_407_response(result), \
                f"Expected 407 response, got http_code={result.stdout}, " \
                f"returncode={result.returncode}, stderr={result.stderr}"

        finally:
            if entry_proc:
                entry_proc.send_signal(signal.SIGTERM)
                entry_proc.wait(timeout=10)
            if upstream_proc:
                upstream_proc.send_signal(signal.SIGTERM)
                upstream_proc.wait(timeout=10)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


class TestNegativeAuthSOCKS5Entry:
    """Negative tests for SOCKS5 entry proxy authentication."""

    def test_socks5_entry_wrong_credentials_fails(self) -> None:
        """TC-NEG-AUTH-003: SOCKS5 entry with wrong credentials fails.

        When a SOCKS5 proxy requires password authentication and the client
        sends incorrect credentials, the connection must be rejected.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        socks5_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: Optional[subprocess.Popen] = None
        entry_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir1)

            # Start upstream HTTP/3 without auth (entry auth is what we test)
            upstream_config = create_upstream_no_auth_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream HTTP/3 listener failed to start"

            # Start entry SOCKS5 with password auth
            entry_config = create_entry_socks5_no_upstream_auth_config(
                socks5_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", socks5_port, timeout=5.0), \
                "Entry SOCKS5 listener failed to start"

            time.sleep(0.5)

            # Send request with wrong SOCKS5 credentials
            result = subprocess.run(
                [
                    "curl", "--socks5-basic", "--socks5-hostname",
                    f"127.0.0.1:{socks5_port}",
                    "--proxy-user", "wrong_user:wrong_pass",
                    "https://www.baidu.com", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}", "--connect-timeout", "5"
                ],
                capture_output=True, text=True
            )

            # SOCKS5 auth failure: curl returns non-zero exit code
            # or a non-200 HTTP code depending on curl version.
            # The important thing is it does NOT return 200.
            assert result.stdout != "200", \
                f"Expected non-200 response for wrong SOCKS5 credentials, " \
                f"got {result.stdout}. stderr: {result.stderr}"

        finally:
            if entry_proc:
                entry_proc.send_signal(signal.SIGTERM)
                entry_proc.wait(timeout=10)
            if upstream_proc:
                upstream_proc.send_signal(signal.SIGTERM)
                upstream_proc.wait(timeout=10)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


class TestNegativeAuthUpstream:
    """Negative tests for upstream proxy authentication."""

    def test_wrong_upstream_credentials_connection_fails(self) -> None:
        """TC-NEG-AUTH-004: Wrong upstream credentials cause connection failure.

        When the http3_chain service is configured with wrong credentials for
        the upstream proxy, the CONNECT request to the upstream should be
        rejected, and the client should receive a non-200 response.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: Optional[subprocess.Popen] = None
        entry_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir1)

            # Start upstream HTTP/3 WITH password auth (user1:pass1)
            upstream_config = create_upstream_password_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream HTTP/3 listener failed to start"

            # Start entry HTTP with WRONG upstream credentials (wrong_user:wrong_pass)
            entry_config = create_entry_http_wrong_upstream_auth_config(
                http_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "Entry HTTP listener failed to start"

            time.sleep(0.5)

            # Send request with correct entry credentials but wrong upstream creds.
            # The upstream should reject the CONNECT request with 407,
            # which the entry proxy may forward back to the client or
            # report as a connection failure (502 Bad Gateway).
            result = subprocess.run(
                [
                    "curl", "-x", f"http://user1:pass1@127.0.0.1:{http_port}",
                    "https://www.baidu.com", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}", "--connect-timeout", "10"
                ],
                capture_output=True, text=True
            )

            # The request must NOT succeed (non-200).
            # Depending on how http3_chain handles upstream auth failure,
            # we may see: 407 (forwarded), 502 (bad gateway), or curl error.
            http_code = result.stdout.strip()
            assert http_code != "200", \
                f"Expected non-200 response for wrong upstream credentials, " \
                f"got {http_code}. stderr: {result.stderr}"

        finally:
            if entry_proc:
                entry_proc.send_signal(signal.SIGTERM)
                entry_proc.wait(timeout=10)
            if upstream_proc:
                upstream_proc.send_signal(signal.SIGTERM)
                upstream_proc.wait(timeout=10)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
