"""HTTP/3 request failures and QUIC configuration boundaries.

Basic handshake, CONNECT and payload contracts live in test_chain_matrix_local.py;
authentication lives in test_chain_matrix_auth.py and test_proxy_auth_challenge.py.
Real active-connection and stalled-stream shutdown contracts live in
test_http3_shutdown.py; idle shutdown latency lives in test_http3_listener.py.
Keep error responses and configuration boundaries separate from those successes.
"""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from tests.fixtures.configuration import StringMap
from tests.fixtures.h3_configuration import (
    create_http3_listener_config,
)
from tests.fixtures.h3_tunnel import (
    H3ConnectResult,
)
from tests.fixtures.http3_client import H3Client
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy


class TestHTTP3ErrorHandling:
    """Test 7.5: HTTP/3 error handling scenarios with real client."""

    def test_non_connect_request_reaches_refused_target(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-ERR-004: A valid H3 GET reaches its HTTPS target.

        H3's scheme, authority and path describe an absolute target, even
        when :path is just '/'. A refused target must return 502 rather
        than rejecting this valid request as an unsupported scheme.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Send a GET request (non-CONNECT) using HTTP/3 client
            async def do_get_request() -> tuple[bool, int, bytes | str]:
                client = H3Client("127.0.0.1", proxy_port, ca_path=ca_path)
                connected = await asyncio.wait_for(client.connect(), timeout=15.0)
                if not connected:
                    return False, 0, "Connection failed"

                response = await asyncio.wait_for(
                    client.send_request(
                        "GET", "/", authority=f"127.0.0.1:{target_port}"
                    ),
                    timeout=15.0,
                )
                await client.close()
                return True, response.status_code, response.body

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, _body = loop.run_until_complete(do_get_request())
            finally:
                loop.close()

            assert success, "HTTP/3 connection failed"
            assert status_code == 502, (
                f"Expected 502 for a refused HTTPS target, got {status_code}"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_target_returns_400(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-ERR-005: Invalid target address returns 400.

        Target: Verify HTTP/3 listener returns 400 for invalid target.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # CONNECT to an invalid target (port 0 is invalid)
            async def do_connect() -> tuple[bool, int, bytes | str]:
                # Try to connect to target with port 0 (invalid)
                # This should be handled by the proxy
                client = H3Client("127.0.0.1", proxy_port, ca_path=ca_path)
                connected = await asyncio.wait_for(client.connect(), timeout=15.0)
                if not connected:
                    return False, 0, "Connection failed"

                # Note: The CONNECT target validation happens at the HTTP/3 layer
                # We send a CONNECT to invalid:0
                response = await asyncio.wait_for(
                    client.send_connect_request("invalid", 0),
                    timeout=15.0,
                )
                await client.close()
                return True, response.status_code, response.body

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, _body = loop.run_until_complete(do_connect())
            finally:
                loop.close()

            # The proxy should return 400 for invalid target
            assert success, "HTTP/3 connection failed"
            assert status_code == 400, f"Expected 400 Bad Request, got {status_code}"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_target_unreachable_returns_502(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-ERR-006: Target unreachable returns 502.

        Target: Verify HTTP/3 listener returns 502 when target is unreachable.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create config with short connect_timeout to make test faster
            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct
        tcp_connect_timeout: 1s

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: direct
  kind: upstream.upstream
  args:
    upstream: direct

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  listeners: ["h3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # CONNECT to an unreachable target
            # Use TEST-NET-2 (198.51.100.0/24) which is non-routable
            async def do_connect() -> H3ConnectResult:
                from tests.fixtures.h3_tunnel import perform_h3_connect_test_full

                result = await perform_h3_connect_test_full(
                    "127.0.0.1",
                    proxy_port,
                    "198.51.100.1",
                    9999,
                    ca_path=ca_path,
                    timeout=10.0,  # Shorter timeout since connect_timeout is 2s
                )
                return result

            # Use a new event loop to avoid conflicts with pytest
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(do_connect())
            finally:
                loop.close()

            # The proxy should return 502 (bad gateway) or 504 (gateway timeout)
            # for unreachable targets. If the client times out before the proxy
            # responds, status_code will be 0.
            assert result.status_code in (502, 504, 0), (
                f"Expected 502/504/timeout, got {result.status_code}. Message:"
                + f" {result.message}"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3ConfigValidationFull:
    """Test 7.7: HTTP/3 configuration validation scenarios."""

    def test_invalid_quic_timeout_uses_default(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-005: Invalid max_idle_timeout uses default.

        Target: Verify HTTP/3 listener uses default for invalid timeout.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Test with zero timeout (invalid, rejected at startup)
            quic_config = """      max_concurrent_bidi_streams: 100
      max_idle_timeout: '0s'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Invalid timeout is rejected at startup (bail!)
            _ = proxy_proc.wait(timeout=5)
            assert proxy_proc.returncode != 0, (
                "HTTP/3 listener should reject invalid max_idle_timeout"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_quic_params_boundary_min_values(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-008: QUIC params at minimum boundary values.

        Target: Verify HTTP/3 listener handles minimum boundary values correctly.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Test minimum valid values
            quic_config = """      max_concurrent_bidi_streams: 1
      max_idle_timeout: '1ms'
      initial_mtu: 1200
      send_window: '1B'
      receive_window: '1B'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Should start with minimum valid values
            if not proxy_proc.wait_ready(timeout=5.0):
                if proxy_proc.poll() is not None:
                    _, stderr_data = proxy_proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener should start with minimum QUIC params")

            assert proxy_proc.poll() is None, "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_quic_params_boundary_max_values(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-009: QUIC params at maximum boundary values.

        Target: Verify HTTP/3 listener handles maximum boundary values correctly.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Test maximum valid values per design doc
            quic_config = """      max_concurrent_bidi_streams: 10000
      max_idle_timeout: '300s'
      initial_mtu: 9000
      send_window: '100MiB'
      receive_window: '100MiB'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Should start with maximum valid values
            if not proxy_proc.wait_ready(timeout=5.0):
                if proxy_proc.poll() is not None:
                    _, stderr_data = proxy_proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener should start with maximum QUIC params")

            assert proxy_proc.poll() is None, "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.parametrize("field", ["max_concurrent_bidi_streams", "initial_mtu"])
    def test_quic_params_negative_values_rejected(
        self, shared_test_certs: StringMap, field: str
    ) -> None:
        """
        Negative unsigned QUIC parameters fail startup with a logged error.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            quic_config = f"{field}: -1"

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            stdout, stderr = proxy_proc.communicate(timeout=5)
            assert proxy_proc.returncode != 0, (stdout, stderr)
            diagnostic = "\n".join(
                path.read_text()
                for path in (Path(temp_dir) / "logs").glob("neoproxy.log*")
            )
            assert "server thread failed: invalid value: integer `-1`" in diagnostic

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)
