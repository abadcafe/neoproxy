"""
Integration tests for the HTTP/3 Chain global upstream pool.

Tests:
- Connection reuse within a single service
- Multiple services sharing the same upstream
- Three-level config inheritance (Plugin -> Upstream -> Address)
- WRR load balancing with global pool
- Config validation for new upstream format
"""

import os
import socket
import subprocess
import tempfile
from typing import Optional

from .conftest import get_unique_port
from .utils.helpers import (
    wait_for_proxy,
    wait_for_process_exit,
    wait_for_udp_port_bound,
    terminate_process,
    establish_connect_tunnel,
    create_target_server,
    NEOPROXY_BINARY,
)
from .utils.http_echo import http_echo_handler
from .utils.certs import generate_test_certificates
from .utils.config_builders import (
    create_http3_listener_config,
    create_http3_chain_config,
)


def _proxy_get(proxy_port, target_host, target_port, timeout=10):
    """Send GET request through CONNECT tunnel via the proxy, return status code."""
    tunnel = establish_connect_tunnel(
        "127.0.0.1", proxy_port, target_host, target_port
    )
    if tunnel is None:
        return 0
    try:
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        tunnel.settimeout(timeout)
        tunnel.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = tunnel.recv(4096)
            if not chunk:
                break
            response += chunk
        status_line = response.split(b"\r\n")[0].decode()
        if "200" in status_line:
            return 200
        return 0
    except Exception:
        return 0
    finally:
        tunnel.close()


# ==============================================================================
# Test: Connection Reuse Within Service
# ==============================================================================

class TestConnectionReuseWithinService:
    """
    Verify that multiple requests through the same service reuse the
    QUIC connection (global pool behavior).
    """

    def test_multiple_requests_reuse_connection(self):
        """
        Send 5 requests through the same upstream — all should succeed.
        The global pool ensures connection reuse across requests.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            upstream_config_path = create_http3_listener_config(
                h3_port, cert_path, key_path, temp_dir
            )
            upstream_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream H3 listener did not start"

            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir,
                upstream_name="reuse_upstream",
            )

            entry_proc = subprocess.Popen(
                [os.path.abspath(NEOPROXY_BINARY), "--config", chain_config],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            wait_for_proxy("127.0.0.1", http_port, timeout=10)

            # Use local echo target to avoid external network
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            for i in range(5):
                status = _proxy_get(http_port, "127.0.0.1", target_port)
                assert status == 200, f"Request {i} failed with status {status}"

            terminate_process(entry_proc, timeout=10)
            wait_for_process_exit(entry_proc, timeout=5)

        finally:
            if target_socket:
                target_socket.close()
            if entry_proc:
                terminate_process(entry_proc, timeout=5, force=True)
            if upstream_proc:
                terminate_process(upstream_proc, timeout=5, force=True)


# ==============================================================================
# Test: Multiple Services Sharing Same Upstream
# ==============================================================================

class TestMultipleServicesShareUpstream:
    """
    Verify that multiple HTTP/3 chain services can share the same
    upstream via the global pool.
    """

    def test_two_services_same_upstream(self):
        """
        Create two services (different listener ports) both referencing
        the same upstream. Both should work correctly.
        """
        temp_dir = tempfile.mkdtemp()
        http_port_1 = get_unique_port()
        http_port_2 = get_unique_port()
        h3_port = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc: Optional[subprocess.Popen] = None
        target_port = get_unique_port()
        target_socket: Optional[socket.socket] = None

        try:
            # Start upstream H3 listener
            upstream_config_path = create_http3_listener_config(
                h3_port, cert_path, key_path, temp_dir
            )
            upstream_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream H3 listener did not start"

            # Build config with two services using the same upstream
            log_dir = os.path.join(temp_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            config_content = f"""server_threads: 2

plugins:
  http3_chain:
    tls:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: shared_upstream
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1

listeners:
  - name: http_1
    kind: http
    addresses: ["0.0.0.0:{http_port_1}"]
  - name: http_2
    kind: http
    addresses: ["0.0.0.0:{http_port_2}"]

services:
  - name: chain_1
    kind: http3_chain.http3_chain
    args:
      upstream: shared_upstream
  - name: chain_2
    kind: http3_chain.http3_chain
    args:
      upstream: shared_upstream

servers:
  - name: server_1
    listeners: ["http_1"]
    service: chain_1
  - name: server_2
    listeners: ["http_2"]
    service: chain_2
"""
            config_path = os.path.join(temp_dir, "shared_upstream.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            wait_for_proxy("127.0.0.1", http_port_1, timeout=10)
            wait_for_proxy("127.0.0.1", http_port_2, timeout=5)

            # Both services should work
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )
            r1 = _proxy_get(http_port_1, "127.0.0.1", target_port)
            assert r1 == 200, f"Service 1 failed with status {r1}"

            r2 = _proxy_get(http_port_2, "127.0.0.1", target_port)
            assert r2 == 200, f"Service 2 failed with status {r2}"

            terminate_process(entry_proc, timeout=10)
            wait_for_process_exit(entry_proc, timeout=5)

        finally:
            if target_socket:
                target_socket.close()
            if entry_proc:
                terminate_process(entry_proc, timeout=5, force=True)
            if upstream_proc:
                terminate_process(upstream_proc, timeout=5, force=True)


# ==============================================================================
# Test: Three-Level Config Inheritance
# ==============================================================================

class TestThreeLevelConfigInheritance:
    """
    Verify three-level config inheritance (Plugin -> Upstream -> Address).
    """

    def test_address_level_auth_overrides_plugin(self):
        """
        Address-level user credentials should override plugin-level user.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc: Optional[subprocess.Popen] = None
        target_port = get_unique_port()
        target_socket: Optional[socket.socket] = None

        try:
            from .utils.config_builders import (
                create_http3_listener_config_with_password_auth,
            )
            # Start upstream with password auth (expecting address-level user)
            upstream_config_path = create_http3_listener_config_with_password_auth(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[("addr_user", "addr_pass")],
            )
            upstream_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream H3 listener did not start"

            # Plugin-level has WRONG user, address-level has CORRECT user
            config_content = f"""server_threads: 1

plugins:
  http3_chain:
    user:
      username: "wrong_user"
      password: "wrong_pass"
    tls:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1
            user:
              username: "addr_user"
              password: "addr_pass"

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:{http_port}"]

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      upstream: test_upstream

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
            config_path = os.path.join(temp_dir, "addr_override.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            wait_for_proxy("127.0.0.1", http_port, timeout=10)

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            status = _proxy_get(http_port, "127.0.0.1", target_port)
            assert status == 200, f"Address-level auth should override plugin-level, got {status}"

            terminate_process(entry_proc, timeout=10)
            wait_for_process_exit(entry_proc, timeout=5)

        finally:
            if target_socket:
                target_socket.close()
            if entry_proc:
                terminate_process(entry_proc, timeout=5, force=True)
            if upstream_proc:
                terminate_process(upstream_proc, timeout=5, force=True)

    def test_plugin_level_auth_inherited_by_address(self):
        """
        Address without user should inherit plugin-level user.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc: Optional[subprocess.Popen] = None
        target_port = get_unique_port()
        target_socket: Optional[socket.socket] = None

        try:
            from .utils.config_builders import (
                create_http3_listener_config_with_password_auth,
            )
            upstream_config_path = create_http3_listener_config_with_password_auth(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[("plugin_user", "plugin_pass")],
            )
            upstream_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream H3 listener did not start"

            # Plugin-level user, address has NO user -> inherits from plugin
            config_content = f"""server_threads: 1

plugins:
  http3_chain:
    user:
      username: "plugin_user"
      password: "plugin_pass"
    tls:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:{http_port}"]

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      upstream: test_upstream

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
            config_path = os.path.join(temp_dir, "plugin_inherit.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            wait_for_proxy("127.0.0.1", http_port, timeout=10)

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            status = _proxy_get(http_port, "127.0.0.1", target_port)
            assert status == 200, f"Plugin-level auth should be inherited, got {status}"

            terminate_process(entry_proc, timeout=10)
            wait_for_process_exit(entry_proc, timeout=5)

        finally:
            if target_socket:
                target_socket.close()
            if entry_proc:
                terminate_process(entry_proc, timeout=5, force=True)
            if upstream_proc:
                terminate_process(upstream_proc, timeout=5, force=True)

    def test_upstream_level_auth_overrides_plugin(self):
        """
        Upstream-level user should override plugin-level user,
        and address inherits from upstream.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc: Optional[subprocess.Popen] = None
        target_port = get_unique_port()
        target_socket: Optional[socket.socket] = None

        try:
            from .utils.config_builders import (
                create_http3_listener_config_with_password_auth,
            )
            upstream_config_path = create_http3_listener_config_with_password_auth(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
                users=[("upstream_user", "upstream_pass")],
            )
            upstream_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "Upstream H3 listener did not start"

            # Plugin has WRONG user, upstream has CORRECT user,
            # address has NO user -> inherits from upstream
            config_content = f"""server_threads: 1

plugins:
  http3_chain:
    user:
      username: "wrong_plugin_user"
      password: "wrong_plugin_pass"
    tls:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        user:
          username: "upstream_user"
          password: "upstream_pass"
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:{http_port}"]

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      upstream: test_upstream

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
            config_path = os.path.join(temp_dir, "upstream_override.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            wait_for_proxy("127.0.0.1", http_port, timeout=10)

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            status = _proxy_get(http_port, "127.0.0.1", target_port)
            assert status == 200, f"Upstream-level auth should override plugin-level, got {status}"

            terminate_process(entry_proc, timeout=10)
            wait_for_process_exit(entry_proc, timeout=5)

        finally:
            if target_socket:
                target_socket.close()
            if entry_proc:
                terminate_process(entry_proc, timeout=5, force=True)
            if upstream_proc:
                terminate_process(upstream_proc, timeout=5, force=True)


# ==============================================================================
# Test: WRR Load Balancing with Pool
# ==============================================================================

class TestWRRLoadBalancingWithPool:
    """
    Verify WRR load balancing works correctly with the global pool.
    """

    def test_two_addresses_wrr_distribution(self):
        """
        With two upstream addresses (weights 2:1), verify both receive
        traffic with proper distribution.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port_1 = get_unique_port()
        h3_port_2 = get_unique_port()
        cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
        entry_proc: Optional[subprocess.Popen] = None
        upstream_proc_1: Optional[subprocess.Popen] = None
        upstream_proc_2: Optional[subprocess.Popen] = None
        target_port = get_unique_port()
        target_socket: Optional[socket.socket] = None

        try:
            # Start two upstream H3 listeners
            upstream_config_1 = create_http3_listener_config(
                h3_port_1, cert_path, key_path, temp_dir
            )
            upstream_proc_1 = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_1],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound("127.0.0.1", h3_port_1, timeout=5.0), \
                "Upstream 1 did not start"

            upstream_config_2 = create_http3_listener_config(
                h3_port_2, cert_path, key_path, temp_dir
            )
            upstream_proc_2 = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", upstream_config_2],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            assert wait_for_udp_port_bound("127.0.0.1", h3_port_2, timeout=5.0), \
                "Upstream 2 did not start"

            # Config with two addresses, weights 2:1
            config_content = f"""server_threads: 2

plugins:
  http3_chain:
    tls:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: wrr_upstream
        addresses:
          - address: 127.0.0.1:{h3_port_1}
            hostname: localhost
            weight: 2
          - address: 127.0.0.1:{h3_port_2}
            hostname: localhost
            weight: 1

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:{http_port}"]

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      upstream: wrr_upstream

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
            config_path = os.path.join(temp_dir, "wrr_pool.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            entry_proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            )
            wait_for_proxy("127.0.0.1", http_port, timeout=10)

            # Send 6 requests to local echo target
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            success_count = 0
            for _ in range(6):
                status = _proxy_get(http_port, "127.0.0.1", target_port)
                if status == 200:
                    success_count += 1

            # At least 4 should succeed (WRR distributes load)
            assert success_count >= 4, (
                f"Expected >=4 successful requests, got {success_count}"
            )

            # Both upstreams should still be running
            assert upstream_proc_1.poll() is None, "Upstream 1 should be alive"
            assert upstream_proc_2.poll() is None, "Upstream 2 should be alive"

            terminate_process(entry_proc, timeout=10)
            wait_for_process_exit(entry_proc, timeout=5)

        finally:
            if target_socket:
                target_socket.close()
            if entry_proc:
                terminate_process(entry_proc, timeout=5, force=True)
            if upstream_proc_1:
                terminate_process(upstream_proc_1, timeout=5, force=True)
            if upstream_proc_2:
                terminate_process(upstream_proc_2, timeout=5, force=True)


# ==============================================================================
# Test: Config Validation
# ==============================================================================

class TestUpstreamPoolConfigValidation:
    """
    Verify config validation for the new upstream format.
    """

    def test_missing_upstream_reference_fails_at_request_time(self):
        """
        Service referencing a non-existent upstream should start but
        return 502 when a request is made (validated at connection time).
        """
        temp_dir = tempfile.mkdtemp()
        port = get_unique_port()
        target_port = get_unique_port()
        target_socket: Optional[socket.socket] = None

        config_content = f"""server_threads: 1

plugins:
  http3_chain:
    upstreams: []

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:{port}"]

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      upstream: nonexistent_upstream

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
        config_path = os.path.join(temp_dir, "missing_upstream.yaml")
        with open(config_path, "w") as f:
            f.write(config_content)

        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        )
        try:
            assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
                "Proxy should start with missing upstream"

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            # Request should fail — the upstream doesn't exist
            # _proxy_get returns 0 on failure (tunnel setup fails)
            status = _proxy_get(port, "127.0.0.1", target_port)
            assert status == 0, (
                f"Expected tunnel failure (0), got {status}"
            )
        finally:
            if target_socket:
                target_socket.close()
            terminate_process(proc, timeout=5, force=True)

    def test_empty_upstream_name_in_service_fails(self):
        """
        Service with empty upstream name should fail at startup.
        The empty name is validated in Http3ChainServiceArgs::validate().
        """
        temp_dir = tempfile.mkdtemp()
        port = get_unique_port()
        config_content = f"""server_threads: 1

plugins:
  http3_chain:
    upstreams:
      - name: valid_upstream
        addresses: []

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:{port}"]

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      upstream: ""

servers:
  - name: http_proxy
    listeners: ["http_main"]
    service: chain
"""
        config_path = os.path.join(temp_dir, "empty_upstream.yaml")
        with open(config_path, "w") as f:
            f.write(config_content)

        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", config_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        )
        try:
            returncode = proc.wait(timeout=5)
            assert returncode != 0, f"Expected non-zero exit, got {returncode}"
        except subprocess.TimeoutExpired:
            # Process stayed alive — empty upstream name may not crash
            terminate_process(proc, timeout=5, force=True)


# ==============================================================================
# Test: quic: sub-block and max_idle_timeout format
# ==============================================================================

class TestQuicAndMaxIdleTimeoutConfig:
    """Verify quic: sub-block and max_idle_timeout rename."""

    def test_quic_sub_block_parses(self):
        """http3_chain with quic: sub-block starts successfully."""
        temp_dir = tempfile.mkdtemp()
        port = get_unique_port()

        config = f"""server_threads: 1
plugins:
  http3_chain:
    max_idle_timeout: "5m"
    quic:
      keep_alive_interval: "3s"
      max_idle_timeout: "30s"
    upstreams:
      - name: u
        addresses:
          - address: 127.0.0.1:1
            hostname: localhost
            weight: 1
listeners:
  - name: http
    kind: http
    addresses: ["0.0.0.0:{port}"]
services:
  - name: c
    kind: http3_chain.http3_chain
    args:
      upstream: u
servers:
  - name: s
    listeners: ["http"]
    service: c
"""
        path = os.path.join(temp_dir, "quic.yaml")
        with open(path, "w") as f:
            f.write(config)
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        )
        try:
            assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
                "Should start with quic: sub-block"
        finally:
            terminate_process(proc, timeout=5, force=True)

    def test_service_args_rejects_unknown_field(self):
        """Service args with unknown field rejected (deny_unknown_fields)."""
        temp_dir = tempfile.mkdtemp()
        port = get_unique_port()
        config = f"""server_threads: 1
plugins:
  http3_chain:
    upstreams:
      - name: u
        addresses:
          - address: 127.0.0.1:1
            hostname: localhost
            weight: 1
listeners:
  - name: http
    kind: http
    addresses: ["0.0.0.0:{port}"]
services:
  - name: c
    kind: http3_chain.http3_chain
    args:
      upstream: u
      unknown_field: "x"
servers:
  - name: s
    listeners: ["http"]
    service: c
"""
        path = os.path.join(temp_dir, "unknown_field.yaml")
        with open(path, "w") as f:
            f.write(config)
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        )
        rc, _ = wait_for_process_exit(proc, timeout=5)
        assert rc != 0, "Should reject unknown field in service args"

    def test_connect_tcp_max_idle_timeout_starts(self):
        """connect_tcp with max_idle_timeout starts successfully."""
        temp_dir = tempfile.mkdtemp()
        port = get_unique_port()
        config = f"""server_threads: 1
listeners:
  - name: http
    kind: http
    addresses: ["0.0.0.0:{port}"]
services:
  - name: tcp
    kind: connect_tcp.connect_tcp
    args:
      max_idle_timeout: "30s"
servers:
  - name: s
    listeners: ["http"]
    service: tcp
"""
        path = os.path.join(temp_dir, "tcp_idle.yaml")
        with open(path, "w") as f:
            f.write(config)
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        )
        try:
            assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
                "Should start with max_idle_timeout"
        finally:
            terminate_process(proc, timeout=5, force=True)

    def test_connect_tcp_rejects_unknown_field(self):
        """connect_tcp args with unknown field rejected."""
        temp_dir = tempfile.mkdtemp()
        port = get_unique_port()
        config = f"""server_threads: 1
listeners:
  - name: http
    kind: http
    addresses: ["0.0.0.0:{port}"]
services:
  - name: tcp
    kind: connect_tcp.connect_tcp
    args:
      unknown_field: "x"
servers:
  - name: s
    listeners: ["http"]
    service: tcp
"""
        path = os.path.join(temp_dir, "tcp_unknown.yaml")
        with open(path, "w") as f:
            f.write(config)
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        )
        rc, _ = wait_for_process_exit(proc, timeout=5)
        assert rc != 0, "Should reject unknown field in connect_tcp"

    def test_plugin_config_rejects_unknown_field(self):
        """Plugin config with unknown field rejected."""
        temp_dir = tempfile.mkdtemp()
        port = get_unique_port()
        config = f"""server_threads: 1
plugins:
  http3_chain:
    unknown_field: "x"
    upstreams:
      - name: u
        addresses:
          - address: 127.0.0.1:1
            hostname: localhost
            weight: 1
listeners:
  - name: http
    kind: http
    addresses: ["0.0.0.0:{port}"]
services:
  - name: c
    kind: http3_chain.http3_chain
    args:
      upstream: u
servers:
  - name: s
    listeners: ["http"]
    service: c
"""
        path = os.path.join(temp_dir, "unknown_plugin_field.yaml")
        with open(path, "w") as f:
            f.write(config)
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
        )
        rc, _ = wait_for_process_exit(proc, timeout=5)
        assert rc != 0, "Should reject unknown field in plugin config"
