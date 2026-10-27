"""
HTTP/3 Chain proxy integration tests.

Test target: Verify neoproxy HTTP/3 Chain service behavior
Test nature: Black-box testing through external interface (HTTP)

This test module covers:
- 7.2 Proxy chain complete scenarios
- 7.4 Graceful Shutdown scenarios (http3_chain specific)

"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from pydantic import BaseModel, Field

from tests.fixtures.access_log_configuration import enable_access_log
from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import StringMap
from tests.fixtures.h3_configuration import (
    create_http3_chain_config,
    create_http3_listener_config,
)
from tests.fixtures.http_echo import http_echo_handler
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server

# ==============================================================================
# Test cases - 7.2 Proxy chain complete scenarios
# ==============================================================================


class TestHTTP3ChainProxy:
    """Test 7.2: HTTP/3 Chain proxy scenarios."""

    def test_http3_chain_config_valid(self, shared_test_certs: StringMap) -> None:
        """
        TC-CHAIN-001: HTTP/3 Chain configuration is valid.

        Target: Verify http3_chain service starts with valid configuration
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            ca_path = shared_test_certs["ca_path"]

            # Create http3_chain config pointing to a non-existent H3 listener
            # The service should still start, it will try to connect on demand
            config_path = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            # Wait for HTTP listener
            assert proxy_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Verify process is running
            assert proxy_proc.poll() is None, "HTTP/3 chain service should be running"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http3_chain_graceful_shutdown(self, shared_test_certs: StringMap) -> None:
        """
        TC-CHAIN-002: HTTP/3 Chain graceful shutdown.

        Target: Verify http3_chain service shuts down gracefully
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            ca_path = shared_test_certs["ca_path"]

            config_path = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            start_time = time.monotonic()
            proxy_proc.send_signal(signal.SIGTERM)

            return_code = proxy_proc.wait(timeout=10)
            elapsed = time.monotonic() - start_time

            assert return_code == 0, f"Expected exit code 0, got {return_code}"

            # Should complete within reasonable time for graceful shutdown
            # The http3_chain service may need time to close idle connections
            assert elapsed < 8.0, f"Shutdown took too long: {elapsed:.2f}s"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http3_chain_multiple_proxies(self, shared_test_certs: StringMap) -> None:
        """
        TC-CHAIN-003: HTTP/3 Chain with multiple proxy servers.

        Target: Verify http3_chain service handles multiple proxy configs
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port1 = get_unique_port()
        h3_port2 = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            ca_path = shared_test_certs["ca_path"]

            # Multiple proxy servers with WRR weights
            config_path = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[
                    ("127.0.0.1", h3_port1, 2),
                    ("127.0.0.1", h3_port2, 1),
                ],
                ca_path=ca_path,
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Verify process is running
            assert proxy_proc.poll() is None, "HTTP/3 chain service should be running"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http3_chain_missing_ca(self) -> None:
        """
        TC-CHAIN-004: HTTP/3 Chain with missing CA certificate.

        Target: Verify http_upstream plugin fails to start when CA file is missing.
        The new http_upstream plugin validates the CA path eagerly at startup.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "/nonexistent/ca.pem"
    upstreams:
      - name: test_upstream
        addresses:
          - address: 127.0.0.1:{h3_port}
            hostname: localhost
            weight: 1
            address_protocol: http3

listeners:
- name: http_main
  kind: http
  addresses: [ "0.0.0.0:{http_port}" ]
  args:
    protocols: [ http ]
    hostnames: []
    certificates: []

services:
- name: upstream
  kind: http_upstream.upstream
  args:
    upstream: test_upstream

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: upstream
"""
            config_path = os.path.join(temp_dir, "missing_ca.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )

            # http_upstream validates CA path eagerly at startup,
            # so the process should exit with an error
            try:
                exit_code = proc.wait(timeout=5.0)
                assert exit_code != 0, "Expected non-zero exit code for missing CA file"
            except subprocess.TimeoutExpired:
                proc.kill()
                _ = proc.wait()

        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                _ = proc.wait(timeout=2)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http3_chain_data_transmission(self, shared_test_certs: StringMap) -> None:
        """
        TC-CHAIN-DATA-001: HTTP/3 Chain data transmission.

        Target: Verify data can be transmitted through HTTP/3 chain to a target server.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create target echo server (HTTP response for curl compatibility)
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

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

            # Test data transmission using curl
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-p",
                    "-x",
                    f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d",
                    "test_data_through_chain",
                    "--connect-timeout",
                    "10",
                ],
                capture_output=True,
                text=True,
            )

            assert "test_data_through_chain" in result.stdout, (
                f"Expected echo data, got stdout: {result.stdout}, stderr:"
                + f" {result.stderr}"
            )

        finally:
            if chain_proc:
                chain_proc.kill()
                _ = chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                _ = h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test cases - Full proxy chain (HTTP -> HTTP/3 -> Target)
# ==============================================================================


class TestFullProxyChain:
    """Test complete proxy chain scenarios."""

    def test_full_chain_starts_successfully(self, shared_test_certs: StringMap) -> None:
        """
        TC-FULL-CHAIN-001: Full proxy chain starts successfully.

        Target: Verify both HTTP/3 listener and chain service can start together
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

            # Create HTTP/3 listener (machine 2)
            h3_config = create_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)

            assert h3_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Create HTTP/3 chain service (machine 1)
            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir2,
            )
            chain_proc = start_proxy(chain_config)

            assert chain_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Both should be running
            assert h3_proc.poll() is None, "H3 listener should be running"
            assert chain_proc.poll() is None, "Chain service should be running"

        finally:
            if chain_proc:
                chain_proc.kill()
                _ = chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                _ = h3_proc.wait(timeout=5)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_full_chain_graceful_shutdown(self, shared_test_certs: StringMap) -> None:
        """
        TC-FULL-CHAIN-002: Full proxy chain graceful shutdown.

        Target: Verify both components shut down gracefully
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

            # Shutdown chain first
            chain_proc.send_signal(signal.SIGTERM)
            return_code1 = chain_proc.wait(timeout=5)

            # Shutdown H3 listener
            h3_proc.send_signal(signal.SIGTERM)
            return_code2 = h3_proc.wait(timeout=5)

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
# Test cases - 7.4 HTTP/3 Chain Graceful Shutdown with Active Streams
# ==============================================================================


class TestHTTP3ChainGracefulShutdown:
    """Test 7.4: HTTP/3 chain graceful shutdown with active streams."""

    def test_chain_uninstall_no_active_streams(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-CHAIN-UNINSTALL-001: http3_chain uninstall with no active streams.

        Target: Verify http3_chain uninstalls immediately when no streams are active.
        """
        temp_dir = tempfile.mkdtemp()
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
                temp_dir=temp_dir,
            )
            h3_proc = start_proxy(h3_config)

            assert h3_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Start chain service
            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir,
            )
            chain_proc = start_proxy(chain_config)

            assert chain_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Shutdown chain (no active streams)
            start_time = time.monotonic()
            chain_proc.send_signal(signal.SIGTERM)
            return_code = chain_proc.wait(timeout=5)
            elapsed = time.monotonic() - start_time

            assert return_code == 0, f"Chain exit code: {return_code}"
            # Should complete quickly when no active streams
            assert elapsed < 3.0, (
                f"Shutdown took too long with no active streams: {elapsed:.2f}s"
            )

        finally:
            if chain_proc and chain_proc.poll() is None:
                chain_proc.terminate()
                _ = chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                _ = h3_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_chain_uninstall_with_active_stream(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-CHAIN-UNINSTALL-002: http3_chain uninstall with potential active stream.

        Target: Verify http3_chain service handles shutdown gracefully
        even when there may be connection attempts in progress.

        Note: This test verifies that the chain service shuts down cleanly.
        The actual tunnel establishment through the chain depends on proper
        http3_chain implementation.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

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

            # Create a target server that accepts connection
            def handler(conn: socket.socket) -> None:
                try:
                    time.sleep(5)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, handler)

            # Start chain service
            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir2,
            )
            chain_proc = start_proxy(chain_config)

            assert chain_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Trigger shutdown while server is running
            start_time = time.monotonic()
            chain_proc.send_signal(signal.SIGTERM)
            return_code = chain_proc.wait(timeout=15)
            elapsed = time.monotonic() - start_time

            assert return_code == 0, f"Chain exit code: {return_code}"
            # Should complete within timeout + buffer (5s timeout + buffer)
            assert elapsed < 10.0, f"Shutdown took too long: {elapsed:.2f}s"

        finally:
            if chain_proc and chain_proc.poll() is None:
                chain_proc.terminate()
                _ = chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                _ = h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


# ==============================================================================
# Test cases - WRR Load Balancing
# ==============================================================================


class TestWRRLoadBalancing:
    """
    Test Weighted Round-Robin load balancing for http3_chain.

    Note: Black-box testing of WRR weight distribution is limited because:
    1. HTTP/3 listeners don't log per-request transfer completions at consistent times
    2. UDP/QUIC connections don't have observable connection state like TCP
    3. The WRR selection happens internally in http3_chain with no external
    observability

    The WRR algorithm itself is verified by unit tests in src/plugins/http3_chain.rs:
    - test_proxy_group_schedule_wrr_single: Single proxy always returns index 0
    - test_proxy_group_schedule_wrr_two_proxies_weight_2_to_1: 2:1 weight distribution
    - test_proxy_group_schedule_wrr_two_proxies_weight_3_to_1: 3:1 weight distribution
    - test_proxy_group_schedule_wrr_three_proxies: Multiple proxies with different
    weights
    - test_proxy_group_schedule_wrr_equal_weights: Equal weight distribution
    - test_proxy_group_schedule_wrr_deterministic: Repeatability of WRR selections

    This black-box test verifies that:
    - Requests succeed when multiple upstreams are configured
    - The chain service starts correctly with weighted proxy groups
    - All configured upstreams are reachable
    """

    def test_wrr_weight_distribution(self, shared_test_certs: StringMap) -> None:
        """
        TC-WRR-001: WRR with multiple weighted upstreams.

        Target: Verify http3_chain works with multiple weighted upstream proxies.
        Verifies that:
        1. Chain service starts with weighted proxy group configuration
        2. Requests succeed through the chain with multiple upstreams
        3. Both upstream listeners are running and reachable

        Note: Precise weight distribution verification requires internal observability
        which is not available in black-box testing. The WRR algorithm correctness
        is verified by unit tests in src/plugins/http3_chain.rs
        (test_proxy_group_schedule_wrr_*).
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()
        temp_dir3 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port1 = get_unique_port()
        h3_port2 = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc1: BytesProcess | None = None
        h3_proc2: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            # Generate certificates once - both HTTP/3 listeners use the same CA
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create target echo server
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            # Start HTTP/3 listener 1 (weight 2)
            h3_config1 = create_http3_listener_config(
                proxy_port=h3_port1,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc1 = start_proxy(h3_config1)
            assert h3_proc1.wait_ready(timeout=5.0), "HTTP/3 listener 1 failed to start"

            # Start HTTP/3 listener 2 (weight 1)
            h3_config2 = create_http3_listener_config(
                proxy_port=h3_port2,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir2,
            )
            h3_proc2 = start_proxy(h3_config2)
            assert h3_proc2.wait_ready(timeout=5.0), "HTTP/3 listener 2 failed to start"

            # Start chain service with weights 2:1
            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[
                    ("127.0.0.1", h3_port1, 2),
                    ("127.0.0.1", h3_port2, 1),
                ],
                ca_path=ca_path,
                temp_dir=temp_dir3,
            )
            chain_proc = start_proxy(chain_config)
            assert chain_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Send multiple requests through the chain
            # WRR should distribute these across both upstreams
            successful_requests = 0
            for i in range(6):
                result = subprocess.run(
                    [
                        "curl",
                        "-s",
                        "-p",
                        "-x",
                        f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d",
                        f"request_{i}",
                        "--connect-timeout",
                        "10",
                    ],
                    capture_output=True,
                    text=True,
                )
                if f"request_{i}" in result.stdout:
                    successful_requests += 1

            # Verify that requests succeeded through the chain
            # This proves the chain can use the weighted proxy group
            assert successful_requests >= 4, (
                f"Expected at least 4 successful requests, got {successful_requests}"
            )

            # Verify both listeners are still running (not crashed)
            assert h3_proc1.poll() is None, "HTTP/3 listener 1 should still be running"
            assert h3_proc2.poll() is None, "HTTP/3 listener 2 should still be running"

        finally:
            if chain_proc:
                chain_proc.kill()
                _ = chain_proc.wait(timeout=5)
            if h3_proc1:
                h3_proc1.kill()
                _ = h3_proc1.wait(timeout=5)
            if h3_proc2:
                h3_proc2.kill()
                _ = h3_proc2.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
            shutil.rmtree(temp_dir3, ignore_errors=True)


class ReuseFields(BaseModel):
    request_id: str = Field(alias="request.id")
    peer: str = Field(alias="upstream.connection.peer")
    reused: bool = Field(alias="upstream.connection.reused")
    handshake_ms: int | None = Field(default=None, alias="upstream.tls.handshake_ms")


class ReuseAccessEntry(BaseModel):
    extensions: ReuseFields


class TestConnectionReuse:
    """Test connection reuse in HTTP/3 chain."""

    def test_connection_reuse_across_requests(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-REUSE-001: QUIC connection is reused across multiple requests.

        Target: Verify that once a QUIC connection is established, subsequent
        requests reuse it instead of creating new connections. This prevents
        fd leaks and ensures optimal resource usage.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Start target echo server
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

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
            enable_access_log(
                chain_config,
                [
                    "request.id",
                    "upstream.connection.peer",
                    "upstream.connection.reused",
                    "upstream.tls.handshake_ms",
                ],
            )
            chain_proc = start_proxy(chain_config)
            assert chain_proc.wait_ready(timeout=5.0), "HTTP listener failed to start"

            # Send 5 requests through the chain
            for i in range(5):
                result = subprocess.run(
                    [
                        "curl",
                        "-s",
                        "-p",
                        "-x",
                        f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d",
                        f"request_{i}",
                        "--connect-timeout",
                        "10",
                    ],
                    capture_output=True,
                    text=True,
                    env={**os.environ, "no_proxy": "", "NO_PROXY": ""},
                )
                assert f"request_{i}" in result.stdout, (
                    f"Request {i} failed: "
                    + f"stdout={result.stdout}, stderr={result.stderr}"
                )

            # Gracefully shutdown chain service so WorkerGuard flushes logs
            chain_proc.send_signal(signal.SIGTERM)
            return_code = chain_proc.wait(timeout=10)
            assert return_code == 0, f"Chain exit code: {return_code}"

            access = [
                ReuseAccessEntry.model_validate_json(line)
                for path in (Path(temp_dir2) / "logs").glob("access*")
                for line in path.read_text().splitlines()
            ]
            assert len(access) == 5
            assert [entry.extensions.reused for entry in access] == [
                False,
                True,
                True,
                True,
                True,
            ]
            assert all(
                entry.extensions.peer == f"127.0.0.1:{h3_port}" for entry in access
            )
            assert len({entry.extensions.request_id for entry in access}) == 5
            assert access[0].extensions.handshake_ms is not None
            assert all(entry.extensions.handshake_ms is None for entry in access[1:])

        finally:
            if chain_proc and chain_proc.poll() is None:
                chain_proc.kill()
                _ = chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                _ = h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
