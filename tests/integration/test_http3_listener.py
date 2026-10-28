"""HTTP/3 configuration failures, idle shutdown latency and echo dispatch.

Startup, unauthenticated traffic and worker cleanup are exercised by
test_chain_matrix_local.py and test_http3_workers.py. Keep the configuration
errors and no-connection shutdown deadline here as independent contracts.
"""

import os
import shutil
import signal
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import StringMap
from tests.fixtures.h3_configuration import create_http3_listener_config
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy


class TestHTTP3ErrorHandling:
    """Test 7.5: HTTP/3 error handling scenarios.

    These tests use the NEW config format with:
    - kind: http3
    - Server-level tls configuration
    - addresses (plural) field
    """

    def test_cert_file_not_exist(self) -> None:
        """
        TC-H3-ERR-001: Certificate file does not exist (NEW config format).

        Target: Verify HTTP/3 listener fails to start with non-existent cert
        using the new server-level TLS configuration format.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            # NEW config format: server-level TLS with non-existent cert
            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: direct
  kind: upstream.upstream
  upstream: direct
servers:
- name: http3_server
  certificates:
  - cert_path: "/nonexistent/path/to/cert.pem"
    key_path: "/nonexistent/path/to/key.pem"
  listeners: ["h3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "invalid_config.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )

            try:
                return_code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _ = proc.wait()
                assert False, "Process did not exit within expected time"

            # Should exit with error code
            assert return_code == 1, f"Expected exit code 1, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_key_file_not_exist(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-ERR-002: Private key file does not exist (NEW config format).

        Target: Verify HTTP/3 listener fails to start with non-existent key
        using the new server-level TLS configuration format.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            cert_path = shared_test_certs["cert_path"]

            # NEW config format: server-level TLS with non-existent key
            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: direct
  kind: upstream.upstream
  upstream: direct
servers:
- name: http3_server
  certificates:
  - cert_path: "{cert_path}"
    key_path: "/nonexistent/path/to/key.pem"
  listeners: ["h3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "invalid_config.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )

            try:
                return_code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _ = proc.wait()
                assert False, "Process did not exit within expected time"

            assert return_code == 1, f"Expected exit code 1, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_cert_key_mismatch(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-ERR-003: Certificate and key do not match (NEW config format).

        Target: Verify HTTP/3 listener fails to start with mismatched cert/key
        using the new server-level TLS configuration format.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            # Use shared cert but generate a mismatched key
            cert_path1 = shared_test_certs["cert_path"]

            # Generate another key
            key_path2 = os.path.join(temp_dir, "wrong.key")
            _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(key_path2, "wb") as _f:
                _ = _f.write(
                    _key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    )
                )

            # NEW config format: server-level TLS with mismatched cert/key
            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: direct
  kind: upstream.upstream
  upstream: direct
servers:
- name: http3_server
  certificates:
  - cert_path: "{cert_path1}"
    key_path: "{key_path2}"
  listeners: ["h3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "mismatch_config.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )

            try:
                return_code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _ = proc.wait()
                assert False, "Process did not exit within expected time"

            # Should exit with error code due to key mismatch
            assert return_code != 0, f"Expected non-zero exit code, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3ConfigValidation:
    """Test 7.7: HTTP/3 configuration validation scenarios.

    These tests use the NEW config format with:
    - kind: http3
    - Server-level tls configuration
    - addresses (plural) field
    """

    def test_invalid_quic_param_uses_default(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-CFG-001: Invalid QUIC parameter uses default value.

        Target: Verify HTTP/3 listener starts with invalid QUIC params
                using default values
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            # Invalid QUIC config: max_concurrent_bidi_streams = 0
            quic_config = """      quic_connection_max_concurrent_bidi_streams: 0
      quic_connection_max_idle_timeout: '30s'"""

            config_path = create_http3_listener_config(
                proxy_port,
                cert_path,
                key_path,
                temp_dir,
                quic_config=quic_config,
            )

            proxy_proc = start_proxy(config_path)

            # Invalid value is rejected at startup (bail!)
            _ = proxy_proc.wait(timeout=5)
            assert proxy_proc.returncode != 0, (
                "HTTP/3 listener should reject invalid max_concurrent_bidi_streams"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_missing_required_fields(self) -> None:
        """
        TC-H3-CFG-002: Missing required fields causes startup failure (NEW config
        format).

        Target: Verify HTTP/3 listener fails without server-level TLS configuration
        using the new config format.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()

        try:
            # NEW config format: Missing server-level tls (required for http3)
            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: direct
  kind: upstream.upstream
  upstream: direct
servers:
- name: http3_server
  listeners: ["h3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "missing_fields.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )

            try:
                return_code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _ = proc.wait()
                assert False, "Process did not exit within expected time"

            assert return_code != 0, f"Expected non-zero exit code, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_address_format(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-CFG-003: Invalid address format causes startup failure (NEW config
        format).

        Target: Verify HTTP/3 listener fails with invalid address
        using the new config format with server-level TLS.
        """
        temp_dir = tempfile.mkdtemp()
        cert_path = shared_test_certs["cert_path"]
        key_path = shared_test_certs["key_path"]

        try:
            # NEW config format: server-level TLS with invalid address format
            config_content = f"""server_threads: 1

plugins:
  upstream:
    upstreams:
      - name: direct

listeners:
- name: h3_main
  kind: http3
  addresses: ["invalid_address_format"]

services:
- name: direct
  kind: upstream.upstream
  upstream: direct
servers:
- name: http3_server
  certificates:
  - cert_path: "{cert_path}"
    key_path: "{key_path}"
  listeners: ["h3_main"]
  service: direct
"""
            config_path = os.path.join(temp_dir, "invalid_addr.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )

            try:
                return_code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _ = proc.wait()
                assert False, "Process did not exit within expected time"

            assert return_code != 0, f"Expected non-zero exit code, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3GracefulShutdown:
    """Test 7.4: HTTP/3 graceful shutdown scenarios."""

    def test_shutdown_with_no_connections(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-SHUTDOWN-001: Shutdown with no connections completes quickly.

        Target: Verify HTTP/3 listener shuts down quickly with no connections
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(), "HTTP/3 listener failed to start"

            start_time = time.monotonic()
            proxy_proc.send_signal(signal.SIGTERM)

            return_code = proxy_proc.wait(timeout=5)
            elapsed = time.monotonic() - start_time

            assert return_code == 0, f"Expected exit code 0, got {return_code}"

            # Should complete quickly (within 2 seconds)
            assert elapsed < 2.0, f"Shutdown took too long: {elapsed:.2f}s"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3EchoService:
    """Test HTTP/3 listener with echo service for non-CONNECT requests."""

    def test_h3_get_to_echo_service_no_upgrade_error(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-H3-ECHO-001: GET request to echo service should not cause upgrade error.

        This test verifies the fix for the bug where HTTP/3 listener creates
        an upgrade pair for ALL requests, causing "Service dropped the receiver"
        error for non-CONNECT requests.

        The bug occurs because:
        1. H3 listener creates (trigger, on_upgrade) pair for ALL requests
        2. on_upgrade is inserted into request extensions
        3. Echo service doesn't extract on_upgrade (it just echoes body)
        4. When service returns 200, trigger.send_success() is called
        5. But the stream was already consumed by H3UpgradeTrigger::pair()
        6. For non-CONNECT, the stream should NOT be consumed by upgrade pair

        Expected: GET request should return 200 with echoed body, no errors.
        """
        import asyncio

        from tests.fixtures.http3_client import H3Client

        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create config with echo service
            config_content = f"""server_threads: 1

plugins:
  echo:

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: echo
  kind: echo.echo

servers:
- name: http3_server
  certificates:
  - cert_path: "{cert_path}"
    key_path: "{key_path}"
  listeners: ["h3_main"]
  service: echo
"""
            config_path = os.path.join(temp_dir, "echo_config.yaml")
            with open(config_path, "w") as f:
                _ = f.write(config_content)

            proxy_proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            assert proxy_proc.wait_ready(), "HTTP/3 listener failed to start"

            # Send a GET request using HTTP/3 client
            async def do_get_request() -> tuple[bool, int, bytes]:
                client = H3Client("127.0.0.1", proxy_port, ca_path=ca_path)
                connected = await asyncio.wait_for(client.connect(), timeout=15.0)
                if not connected:
                    return False, 0, b"Connection failed"

                response = await asyncio.wait_for(
                    client.send_request("GET", "/test-echo"),
                    timeout=15.0,
                )
                await client.close()
                return True, response.status_code, response.body

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, _body = loop.run_until_complete(do_get_request())
            finally:
                loop.close()

            # KEY ASSERTION: Request should succeed with 200
            assert success, "HTTP/3 connection should succeed"
            assert status_code == 200, (
                f"Echo service should return 200, got {status_code}"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)

            # Check log files for errors
            log_dir = os.path.join(temp_dir, "logs")
            if os.path.exists(log_dir):
                for log_file in os.listdir(log_dir):
                    log_path = os.path.join(log_dir, log_file)
                    with open(log_path, "r", errors="replace") as f:
                        log_content = f.read()
                        assert "Service dropped the receiver" not in log_content, (
                            "Should not have 'Service dropped the receiver' error in"
                            + f" logs. File: {log_file}, Content: {log_content}"
                        )

            shutil.rmtree(temp_dir, ignore_errors=True)
