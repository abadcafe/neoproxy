"""
Black-box integration tests for the new unified authentication YAML format.

Tests validate that the new configuration format works correctly:
- Listener auth: no 'type' field, 'users' field directly under 'auth'
- http3_chain: 'credential' replaces 'auth', 'default_credential' replaces 'default_upstream_auth'
- Empty object 'credential: {}' means no credential (override)
- Single object (not array) for auth/credential config
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
)

from .test_http3_listener import (
    generate_test_certificates,
    wait_for_udp_port,
)
from .test_http3_chain import (
    _http_echo_handler,
)
from .utils.helpers import create_target_server


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
# Test: hyper.listener with new auth format (no 'type' field)
# ==============================================================================


class TestHyperListenerNewAuthFormat:
    """Test hyper.listener with new auth format: auth.users directly, no type field."""

    def test_hyper_password_auth_new_format(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-001: hyper.listener accepts new auth format without 'type' field.

        Config:
          auth:
            users:
              - username: testuser
                password: testpass

        Expected: proxy starts, rejects unauthenticated requests (407),
                  accepts authenticated requests.
        """
        port = get_unique_port()
        config = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

servers:
  - name: test
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{port}"]
          protocols: [http]
          hostnames: []
          auth:
            users:
              - username: testuser
                password: testpass
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
# Test: fast_socks5.listener with new auth format
# ==============================================================================


class TestSocks5ListenerNewAuthFormat:
    """Test fast_socks5.listener with new auth format."""

    def test_socks5_password_auth_new_format(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-002: fast_socks5.listener accepts new auth format without 'type' field.

        Config:
          auth:
            users:
              - username: socks_user
                password: socks_pass

        Expected: proxy starts, SOCKS5 auth handshake works with correct credentials.
        """
        port = get_unique_port()
        config = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

servers:
  - name: test
    listeners:
      - kind: fast_socks5.listener
        args:
          addresses: ["127.0.0.1:{port}"]
          auth:
            users:
              - username: socks_user
                password: socks_pass
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
                "Proxy should start with new SOCKS5 auth format"

            # Test: SOCKS5 with correct credentials should succeed
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--socks5", f"127.0.0.1:{port}",
                 "--proxy-user", "socks_user:socks_pass",
                 "http://example.com:80"],
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
    """Test that invalid new auth format configs are rejected at startup."""

    def test_empty_auth_object_rejected_for_listener(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-003: Listener rejects 'auth: {}' (empty object).

        Unlike http3_chain where 'credential: {}' means no-credential override,
        'auth: {}' on a listener is invalid because at least one auth method
        must be specified.
        """
        port = get_unique_port()
        config = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

servers:
  - name: test
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{port}"]
          protocols: [http]
          hostnames: []
          auth: {{}}
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            time.sleep(2)
            started = wait_for_proxy("127.0.0.1", port, timeout=3.0)
            assert not started, \
                "Proxy should NOT start with empty auth object on listener"
        finally:
            terminate_process(proc)

    def test_auth_without_users_or_ca_rejected(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-004: Auth config with neither 'users' nor 'client_ca_path' is rejected.
        """
        port = get_unique_port()
        config = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

servers:
  - name: test
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{port}"]
          protocols: [http]
          hostnames: []
          auth:
            some_unknown_field: true
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            time.sleep(2)
            started = wait_for_proxy("127.0.0.1", port, timeout=3.0)
            assert not started, \
                "Proxy should NOT start with auth missing users and client_ca_path"
        finally:
            terminate_process(proc)

    def test_client_ca_path_rejected_on_hyper_listener(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-005: hyper.listener rejects 'client_ca_path' in auth config.

        Only http3.listener supports TLS client cert auth.
        """
        port = get_unique_port()
        config = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

servers:
  - name: test
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{port}"]
          protocols: [http]
          hostnames: []
          auth:
            client_ca_path: /some/ca.pem
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            time.sleep(2)
            started = wait_for_proxy("127.0.0.1", port, timeout=3.0)
            assert not started, \
                "Proxy should NOT start with client_ca_path on hyper.listener"
        finally:
            terminate_process(proc)

    def test_client_ca_path_rejected_on_socks5_listener(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-006: fast_socks5.listener rejects 'client_ca_path' in auth config.

        Only http3.listener supports TLS client cert auth. SOCKS5 must reject it
        the same way hyper does.
        """
        port = get_unique_port()
        config = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

servers:
  - name: test
    listeners:
      - kind: fast_socks5.listener
        args:
          addresses: ["127.0.0.1:{port}"]
          auth:
            client_ca_path: /some/ca.pem
    service: connect_tcp
"""
        config_path = write_config(temp_dir, config)
        proc = start_proxy(config_path)
        try:
            time.sleep(2)
            started = wait_for_proxy("127.0.0.1", port, timeout=3.0)
            assert not started, \
                "Proxy should NOT start with client_ca_path on fast_socks5.listener"
        finally:
            terminate_process(proc)


# ==============================================================================
# Test: http3_chain with new credential format
# ==============================================================================


class TestHttp3ChainNewCredentialFormat:
    """Test http3_chain with new credential/default_credential format."""

    def _create_http3_upstream_config(
        self,
        temp_dir: str,
        udp_port: int,
        cert_path: str,
        key_path: str,
        auth_users: Optional[List[dict[str, str]]] = None,
    ) -> str:
        """Create an HTTP/3 upstream proxy config (the target proxy in the chain)."""
        auth_block = ""
        if auth_users:
            users_yaml = "\n".join(
                f'              - username: "{u["username"]}"\n'
                f'                password: "{u["password"]}"'
                for u in auth_users
            )
            auth_block = f"""
          auth:
            users:
{users_yaml}"""

        config = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: connect_tcp
    kind: connect_tcp.connect_tcp

servers:
  - name: upstream
    listeners:
      - kind: http3.listener
        args:
          address: "127.0.0.1:{udp_port}"
          cert_path: "{cert_path}"
          key_path: "{key_path}"{auth_block}
    service: connect_tcp
"""
        return write_config(temp_dir, config)

    def test_http3_chain_default_credential_new_format(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-007: http3_chain accepts new 'default_credential' format
        with nested 'user' object instead of old flat 'username'/'password'
        under 'default_upstream_auth' array.

        Config:
          default_credential:
            user:
              username: chain_user
              password: chain_pass

        Expected: proxy starts and the chain proxy can authenticate to upstream.
        """
        # Generate certs for the upstream HTTP/3 proxy
        cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, _http_echo_handler
        )

        # Create upstream HTTP/3 proxy with password auth
        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "chain_user", "password": "chain_pass"}],
        )

        # Create chain proxy with new credential format
        chain_config_content = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          weight: 1
      ca_path: "{ca_path}"
      default_credential:
        user:
          username: chain_user
          password: chain_pass

servers:
  - name: chain
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{http_port}"]
          protocols: [http]
          hostnames: []
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with new default_credential format"

                time.sleep(0.5)

                # Test: Request through chain should succeed (auth should work)
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    [
                        "curl", "-s", "-p", "--http0.9",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_default_credential",
                        "--connect-timeout", "10"
                    ],
                    capture_output=True, text=True, env=env
                )

                assert "test_default_credential" in result.stdout, \
                    f"Expected echo data (auth should work with new format), " \
                    f"got stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()

    def test_http3_chain_per_proxy_credential_override(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-008: http3_chain per-proxy credential override with new format.

        Config:
          proxy_group:
            - address: "upstream:443"
              weight: 1
              credential:
                user:
                  username: special_user
                  password: special_pass

        Expected: proxy starts with per-proxy credential override.
        """
        cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, _http_echo_handler
        )

        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "special_user", "password": "special_pass"}],
        )

        chain_config_content = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          weight: 1
          credential:
            user:
              username: special_user
              password: special_pass
      ca_path: "{ca_path}"
      default_credential:
        user:
          username: default_user
          password: default_pass

servers:
  - name: chain
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{http_port}"]
          protocols: [http]
          hostnames: []
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with per-proxy credential override"

                time.sleep(0.5)

                # Test: Request through chain should succeed (per-proxy credential should work)
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    [
                        "curl", "-s", "-p", "--http0.9",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_per_proxy_credential",
                        "--connect-timeout", "10"
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

    def test_http3_chain_credential_user_format(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-009: http3_chain accepts new 'credential.user' nested format.

        Config:
          proxy_group:
            - address: "upstream:443"
              weight: 1
              credential:
                user:
                  username: override_user
                  password: override_pass
          default_credential:
            user:
              username: default_user
              password: default_pass

        Expected: proxy starts and the per-proxy credential.user is used (not default).

        This test should FAIL in RED phase because:
        - OLD format: credential field with nested 'user' object is not recognized,
          the credential is ignored, no auth sent to upstream, request fails
        - NEW format: credential.user provides auth, request succeeds
        """
        cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, _http_echo_handler
        )

        # Upstream requires auth matching the per-proxy credential (not default)
        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "override_user", "password": "override_pass"}],
        )

        chain_config_content = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          weight: 1
          credential:
            user:
              username: override_user
              password: override_pass
      ca_path: "{ca_path}"
      default_credential:
        user:
          username: default_user
          password: default_pass

servers:
  - name: chain
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{http_port}"]
          protocols: [http]
          hostnames: []
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with new credential.user format"

                time.sleep(0.5)

                # Test: Request should succeed because credential.user provides correct auth
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    [
                        "curl", "-s", "-p", "--http0.9",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_credential_user",
                        "--connect-timeout", "10"
                    ],
                    capture_output=True, text=True, env=env
                )

                assert "test_credential_user" in result.stdout, \
                    f"Expected echo data (credential.user should provide auth), " \
                    f"got stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()

    def test_http3_chain_credential_inheritance(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-010: http3_chain proxy without 'credential' field inherits
        from 'default_credential'.

        Config:
          proxy_group:
            - address: "upstream:443"
              weight: 1
              # No credential field -> inherits default_credential
          default_credential:
            user:
              username: inherited_user
              password: inherited_pass

        Expected: proxy starts and the chain proxy authenticates to upstream
        using the inherited default_credential.
        """
        cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, _http_echo_handler
        )

        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "inherited_user", "password": "inherited_pass"}],
        )

        chain_config_content = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          weight: 1
      ca_path: "{ca_path}"
      default_credential:
        user:
          username: inherited_user
          password: inherited_pass

servers:
  - name: chain
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{http_port}"]
          protocols: [http]
          hostnames: []
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with credential inheritance"

                time.sleep(0.5)

                # Test: Request should succeed (inherited credential should work)
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    [
                        "curl", "-s", "-p", "--http0.9",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_credential_inheritance",
                        "--connect-timeout", "10"
                    ],
                    capture_output=True, text=True, env=env
                )

                assert "test_credential_inheritance" in result.stdout, \
                    f"Expected echo data (inherited credential should work), " \
                    f"got stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()

    def test_http3_chain_credential_empty_object_override(self, temp_dir: str) -> None:
        """
        TC-NEW-AUTH-011: http3_chain 'credential: {}' means explicit no credential,
        overriding default_credential.

        Config:
          proxy_group:
            - address: "upstream:443"
              weight: 1
              credential: {}
          default_credential:
            user:
              username: default_user
              password: default_pass

        Expected: proxy starts. The proxy with credential: {} should NOT send
        any Proxy-Authorization header to upstream, even though default_credential
        is configured.

        Note: This test may PASS in both RED and GREEN phases because the OLD parser
        also treats `credential: {}` as "no credential" (empty object is parsed as
        having no auth fields). The test still validates the expected GREEN phase
        behavior. For a proper RED-phase test, see TC-NEW-AUTH-009 which uses
        `credential.user` format that OLD code doesn't recognize.
        """
        cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(temp_dir)

        upstream_port = get_unique_port()
        http_port = get_unique_port()
        target_port = get_unique_port()

        # Create target server
        _, target_socket = create_target_server(
            "127.0.0.1", target_port, _http_echo_handler
        )

        # Upstream requires auth matching default_credential
        # If credential: {} works (NEW), no auth is sent → upstream rejects
        # If credential: {} is ignored (OLD), default_credential is sent → upstream accepts
        upstream_dir = os.path.join(temp_dir, "upstream")
        os.makedirs(upstream_dir, exist_ok=True)
        upstream_config = self._create_http3_upstream_config(
            upstream_dir, upstream_port, cert_path, key_path,
            auth_users=[{"username": "default_user", "password": "default_pass"}],
        )

        chain_config_content = f"""
worker_threads: 1
log_directory: LOG_DIR_PLACEHOLDER

services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "127.0.0.1:{upstream_port}"
          weight: 1
          credential: {{}}
      ca_path: "{ca_path}"
      default_credential:
        user:
          username: default_user
          password: default_pass

servers:
  - name: chain
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["127.0.0.1:{http_port}"]
          protocols: [http]
          hostnames: []
    service: proxy_chain
"""
        chain_dir = os.path.join(temp_dir, "chain")
        os.makedirs(chain_dir, exist_ok=True)
        chain_config = write_config(chain_dir, chain_config_content)

        upstream_proc = start_proxy(upstream_config)
        try:
            assert wait_for_udp_port("127.0.0.1", upstream_port, timeout=5.0), \
                "Upstream HTTP/3 proxy should start"

            chain_proc = start_proxy(chain_config)
            try:
                assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                    "Chain proxy should start with credential: {} override"

                time.sleep(0.5)

                # Test: Request should FAIL because credential: {} means no auth
                # - NEW behavior: no credential sent → upstream rejects with 401/407
                # - OLD behavior: default_credential sent → upstream accepts
                env = get_curl_env_without_no_proxy()
                result = subprocess.run(
                    [
                        "curl", "-s", "-p", "--http0.9",
                        "-x", f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d", "test_empty_credential",
                        "--connect-timeout", "10"
                    ],
                    capture_output=True, text=True, env=env
                )

                # With NEW format: no echo data because upstream rejects (no auth sent)
                # With OLD format: echo data present because upstream accepts (default used)
                assert "test_empty_credential" not in result.stdout, \
                    f"Expected NO echo data (credential: {{}} should mean no auth), " \
                    f"but got data, meaning OLD format ignored the override. " \
                    f"stdout: {result.stdout}, stderr: {result.stderr}"
            finally:
                terminate_process(chain_proc)
        finally:
            terminate_process(upstream_proc)
            target_socket.close()
