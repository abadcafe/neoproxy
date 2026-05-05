"""
Black-box integration tests for the new unified authentication YAML format.

Tests validate that the new configuration format works correctly:
- Listener auth: no 'type' field, 'users' field directly under 'auth'
- http3_chain: 'user' for authentication, 'tls' for TLS config
- Empty 'user: {}' or missing 'user' means no credential
- Single object (not array) for auth config
- socks5 rejects 'client_ca_path'
"""

import os
import subprocess
import time
from typing import Optional, List

import pytest

from .conftest import get_unique_port
from .utils.helpers import (
    start_proxy,
    terminate_process,
    wait_for_proxy,
    get_curl_env_without_no_proxy,
    wait_for_udp_port_bound,
    create_target_server,
)

from .utils.http_echo import http_echo_handler


def write_config(temp_dir: str, config_content: str) -> str:
    """Write a YAML config to a temp file and return its path."""
    config_path = os.path.join(temp_dir, "config.yaml")
    log_dir = os.path.join(temp_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    config_content = config_content.replace("LOG_DIR_PLACEHOLDER", log_dir)
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# Test: http listener with new auth format (no 'type' field)
# ==============================================================================


class TestHttpListenerNewAuthFormat:
    """Test http listener with new auth format: auth.users directly, no type field."""

    def test_http_password_auth_new_format(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-001: http listener with server-level users config.

        Config:
          users:
            - username: testuser
              password: testpass

        Expected: proxy starts, rejects unauthenticated requests (407),
                  accepts authenticated requests.
        """
        port = get_unique_port()
        config = f"""
server_threads: 1

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: testuser
              password: testpass

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{port}"]

servers:
  - name: test
    listeners: ["http_main"]
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
                "Proxy should start with new auth format"

            # Test: unauthenticated request should get 407
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--proxy", f"127.0.0.1:{port}",
                 "http://example.com:80"],
                capture_output=True, text=True, timeout=10
            )
            assert result.stdout.strip() == "407", \
                f"Expected 407 without auth, got {result.stdout.strip()}"

            # Test: authenticated request should succeed (or at least not 407)
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--proxy", "http://testuser:testpass@127.0.0.1:" + str(port),
                 "http://example.com:80"],
                capture_output=True, text=True, timeout=10
            )
            assert result.stdout.strip() != "407", \
                f"Expected non-407 with valid auth, got {result.stdout.strip()}"
        finally:
            terminate_process(proc)


# ==============================================================================
# Test: socks5 listener with new auth format
# ==============================================================================


class TestSocks5ListenerNewAuthFormat:
    """Test socks5 listener with new auth format."""

    def test_socks5_password_auth_new_format(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-002: socks5 listener accepts new auth format without 'type' field.

        Config:
          auth:
            users:
              - username: socks_user
                password: socks_pass

        Expected: proxy starts, SOCKS5 auth handshake works with correct credentials.
        """
        port = get_unique_port()
        config = f"""
server_threads: 1

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

listeners:
  - name: socks5_main
    kind: socks5
    addresses: ["127.0.0.1:{port}"]
    args:
      users:
        - username: socks_user
          password: socks_pass

servers:
  - name: test
    listeners: ["socks5_main"]
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
                "Proxy should start with new SOCKS5 auth format"

            # Test: SOCKS5 with correct credentials should not fail auth.
            # Use a local unreachable target to avoid DNS/timeout issues;
            # the test only checks that SOCKS5 auth succeeds (not returncode 97).
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--socks5", f"127.0.0.1:{port}",
                 "--proxy-user", "socks_user:socks_pass",
                 "--connect-timeout", "3",
                 "http://127.0.0.1:1"],
                capture_output=True, text=True, timeout=10
            )
            # Should not get connection refused or auth error
            assert result.returncode != 97, \
                "SOCKS5 auth should not fail with correct credentials"
        finally:
            terminate_process(proc)


# ==============================================================================
# Test: Config validation rejects invalid new format
# ==============================================================================


class TestNewAuthFormatValidation:
    """Test that invalid auth configs are rejected at startup."""

    def test_http_listener_ignores_server_level_tls(self, temp_dir: str, shared_test_certs: dict) -> None:
        """
        TC-NEW-AUTH-005: HTTP listener ignores server-level TLS config.

        HTTP is a plaintext protocol and doesn't use TLS. When server-level TLS config
        is present, HTTP listener should simply ignore it and start normally.
        """
        cert_path = shared_test_certs['cert_path']
        key_path = shared_test_certs['key_path']
        ca_path = shared_test_certs['ca_path']

        port = get_unique_port()
        config = f"""
server_threads: 1

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{port}"]

servers:
  - name: test
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
      client_ca_certs:
        - "{ca_path}"
    listeners: ["http_main"]
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            # HTTP listener should start and ignore the server-level TLS config
            started = wait_for_proxy("127.0.0.1", port, timeout=5.0)
            assert started, \
                "HTTP listener should start and ignore server-level TLS config"
        finally:
            terminate_process(proc)

    def test_client_ca_path_rejected_on_socks5_listener(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-006: socks5 listener rejects 'client_ca_path' in auth config.

        Only http3 listener supports TLS client cert auth. SOCKS5 must reject it
        the same way http does.
        """
        port = get_unique_port()
        config = f"""
server_threads: 1

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

listeners:
  - name: socks5_main
    kind: socks5
    addresses: ["127.0.0.1:{port}"]
    args:
      client_ca_path: /some/ca.pem

servers:
  - name: test
    listeners: ["socks5_main"]
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            started = wait_for_proxy("127.0.0.1", port, timeout=3.0)
            assert not started, \
                "Proxy should NOT start with client_ca_path on socks5 listener"
        finally:
            terminate_process(proc)


# ==============================================================================
# Test: http3_chain with new credential format
# ==============================================================================


class TestHttp3ChainNewCredentialFormat:
    """Test http3_chain with new user/tls config format."""

    def _create_http3_upstream_config(
        self,
        temp_dir: str,
        udp_port: int,
        cert_path: str,
        key_path: str,
        auth_users: Optional[List[dict[str, str]]] = None,
    ) -> str:
        """Create an HTTP/3 upstream proxy config (the target proxy in the chain)."""
        layers_block = ""
        if auth_users:
            users_yaml = "\n".join(
                f'          - username: "{u["username"]}"\n'
                f'            password: "{u["password"]}"'
                for u in auth_users
            )
            layers_block = f"""
    layers:
      - kind: auth.basic_auth
        args:
          users:
{users_yaml}"""

        config = f"""
server_threads: 1

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp{layers_block}

listeners:
  - name: h3_main
    kind: http3
    addresses: ["127.0.0.1:{udp_port}"]

servers:
  - name: upstream
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
    listeners: ["h3_main"]
    service: connect_tcp
"""
        return write_config(temp_dir, config)

    def test_http3_chain_default_tls_new_format(self, temp_dir: str, shared_test_certs: dict) -> None:
        """
        TC-NEW-AUTH-007: http3_chain accepts new 'user' and 'tls' format
        with nested 'user' object for authentication and 'tls' for TLS config.

        Config:
          proxy_group:
            - user:
                username: chain_user
                password: chain_pass
          default_tls:
            server_ca_path: ...

        Expected: proxy starts and the chain proxy can authenticate to upstream.
        """
        # Generate certs for the upstream HTTP/3 proxy
        cert_path = shared_test_certs['cert_path']
        key_path = shared_test_certs['key_path']
        ca_path = shared_test_certs['ca_path']

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, http_echo_handler
        )

        # Create upstream HTTP/3 proxy with password auth
        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "chain_user", "password": "chain_pass"}],
        )

        # Create chain proxy with new format
        chain_config_content = f"""
server_threads: 1

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          hostname: localhost
          weight: 1
          user:
            username: chain_user
            password: chain_pass
          tls:
            server_ca_path: "{ca_path}"

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]
    args:
      protocols: [http]
      hostnames: []

servers:
  - name: chain
    listeners: ["http_main"]
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port_bound("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with new user/tls format"


                # Test: Request through chain should succeed (auth should work)
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    ["curl", "-s", "-p",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_default_tls",
                        "--connect-timeout", "10",
                        "--max-time", "2"
                    ],
                    capture_output=True, text=True, env=env
                )

                assert "test_default_tls" in result.stdout, \
                    f"Expected echo data (auth should work with new format), " \
                    f"got stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()

    def test_http3_chain_per_proxy_credential_override(self, temp_dir: str, shared_test_certs: dict) -> None:
        """
        TC-NEW-AUTH-008: http3_chain per-proxy user override with new format.

        Config:
          proxy_group:
            - address: "upstream:443"
              weight: 1
              user:
                username: special_user
                password: special_pass

        Expected: proxy starts with per-proxy user override.
        """
        cert_path = shared_test_certs['cert_path']
        key_path = shared_test_certs['key_path']
        ca_path = shared_test_certs['ca_path']

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, http_echo_handler
        )

        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "special_user", "password": "special_pass"}],
        )

        chain_config_content = f"""
server_threads: 1

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          hostname: localhost
          weight: 1
          user:
            username: special_user
            password: special_pass
          tls:
            server_ca_path: "{ca_path}"

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]
    args:
      protocols: [http]
      hostnames: []

servers:
  - name: chain
    listeners: ["http_main"]
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port_bound("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with per-proxy credential override"


                # Test: Request through chain should succeed (per-proxy credential should work)
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    ["curl", "-s", "-p",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_per_proxy_credential",
                        "--connect-timeout", "10",
                        "--max-time", "2"
                    ],
                    capture_output=True, text=True, env=env
                )

                assert "test_per_proxy_credential" in result.stdout, \
                    f"Expected echo data (per-proxy credential should work), " \
                    f"got stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()

    def test_http3_chain_credential_user_format(self, temp_dir: str, shared_test_certs: dict) -> None:
        """
        TC-NEW-AUTH-009: http3_chain accepts new 'user' nested format.

        Config:
          proxy_group:
            - address: "upstream:443"
              weight: 1
              user:
                username: override_user
                password: override_pass

        Expected: proxy starts and the per-proxy user is used.
        """
        cert_path = shared_test_certs['cert_path']
        key_path = shared_test_certs['key_path']
        ca_path = shared_test_certs['ca_path']

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, http_echo_handler
        )

        # Upstream requires auth matching the per-proxy user
        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "override_user", "password": "override_pass"}],
        )

        chain_config_content = f"""
server_threads: 1

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          hostname: localhost
          weight: 1
          user:
            username: override_user
            password: override_pass
          tls:
            server_ca_path: "{ca_path}"

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]
    args:
      protocols: [http]
      hostnames: []

servers:
  - name: chain
    listeners: ["http_main"]
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port_bound("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with new user format"


                # Test: Request should succeed because user provides correct auth
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    ["curl", "-s", "-p",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_user",
                        "--connect-timeout", "10",
                        "--max-time", "2"
                    ],
                    capture_output=True, text=True, env=env
                )

                assert "test_user" in result.stdout, \
                    f"Expected echo data (user should provide auth), " \
                    f"got stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()

    def test_http3_chain_default_user_inheritance(self, temp_dir: str, shared_test_certs: dict) -> None:
        """
        TC-NEW-AUTH-010: http3_chain proxy inherits from default_user.

        Config:
          default_user:
            username: inherited_user
            password: inherited_pass
          proxy_group:
            - address: "upstream:443"
              weight: 1
              # No user field -> inherits default_user

        Expected: proxy starts and the chain proxy authenticates to upstream
        using the inherited default_user.
        """
        cert_path = shared_test_certs['cert_path']
        key_path = shared_test_certs['key_path']
        ca_path = shared_test_certs['ca_path']

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, http_echo_handler
        )

        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "inherited_user", "password": "inherited_pass"}],
        )

        chain_config_content = f"""
server_threads: 1

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      default_user:
        username: inherited_user
        password: inherited_pass
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          hostname: localhost
          weight: 1
          tls:
            server_ca_path: "{ca_path}"

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]
    args:
      protocols: [http]
      hostnames: []

servers:
  - name: chain
    listeners: ["http_main"]
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port_bound("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with default_user inheritance"


                # Test: Request should succeed (inherited default_user should work)
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    ["curl", "-s", "-p",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_default_user",
                        "--connect-timeout", "10",
                        "--max-time", "2"
                    ],
                    capture_output=True, text=True, env=env
                )

                assert "test_default_user" in result.stdout, \
                    f"Expected echo data (default_user should work), " \
                    f"got stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()

    def test_http3_chain_no_user_no_default(self, temp_dir: str, shared_test_certs: dict) -> None:
        """
        TC-NEW-AUTH-011: http3_chain proxy without 'user' or 'default_user' sends no auth.

        Config:
          proxy_group:
            - address: "upstream:443"
              weight: 1
              # No user field and no default_user -> no auth sent

        Expected: proxy starts. The proxy should NOT send
        any Proxy-Authorization header to upstream.
        """
        cert_path = shared_test_certs['cert_path']
        key_path = shared_test_certs['key_path']
        ca_path = shared_test_certs['ca_path']

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, http_echo_handler
        )

        # Upstream requires auth - if no auth is sent, request should fail
        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "default_user", "password": "default_pass"}],
        )

        chain_config_content = f"""
server_threads: 1

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          hostname: localhost
          weight: 1
          tls:
            server_ca_path: "{ca_path}"

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]
    args:
      protocols: [http]
      hostnames: []

servers:
  - name: chain
    listeners: ["http_main"]
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port_bound("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with no user"


                # Test: Request should FAIL because no auth is sent
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    ["curl", "-s", "-p",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_no_user",
                        "--connect-timeout", "10",
                        "--max-time", "2"
                    ],
                    capture_output=True, text=True, env=env
                )

                # No echo data because upstream rejects (no auth sent)
                assert "test_no_user" not in result.stdout, \
                    f"Expected NO echo data (credential: {{}} should mean no auth), " \
                    f"but got data, meaning OLD format ignored the override. " \
                    f"stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()
