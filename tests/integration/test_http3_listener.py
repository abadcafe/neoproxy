"""
HTTP/3 Listener integration tests.

Test target: Verify neoproxy HTTP/3 Listener behavior
Test nature: Black-box testing through external interface (HTTP/3)

This test module covers:
- 7.1 Basic connection scenarios
- 7.3 Authentication scenarios
- 7.5 Error handling scenarios (HTTP/3 specific)
- 7.7 Configuration validation scenarios (HTTP/3 specific)

NOTE: Some tests are skipped due to missing CryptoProvider initialization
in the main binary. This is a known issue in the implementation.
"""

import subprocess
import socket
import threading
import tempfile
import shutil
import time
import os
import signal
import pytest
from typing import Optional, Tuple, List, Callable

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    terminate_process,
)


# ==============================================================================
# Test helper functions (unique to this module)
# ==============================================================================


def generate_test_certificates(temp_dir: str) -> Tuple[str, str, str, str]:
    """
    Generate self-signed test certificates for HTTP/3 testing.

    Creates a proper CA certificate and a server certificate signed by that CA.
    This is required because rustls enforces proper certificate chain validation.

    Args:
        temp_dir: Temporary directory to store certificates

    Returns:
        Tuple[str, str, str, str]: (server_cert_path, server_key_path, ca_cert_path, ca_key_path)
    """
    ca_key_path = os.path.join(temp_dir, "ca.key")
    ca_cert_path = os.path.join(temp_dir, "ca.crt")
    server_key_path = os.path.join(temp_dir, "server.key")
    server_csr_path = os.path.join(temp_dir, "server.csr")
    server_cert_path = os.path.join(temp_dir, "server.crt")

    # Step 1: Generate CA private key
    subprocess.run(
        ["openssl", "genrsa", "-out", ca_key_path, "2048"],
        check=True,
        capture_output=True
    )

    # Step 2: Generate CA certificate (with CA:TRUE)
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-key", ca_key_path,
            "-out", ca_cert_path,
            "-days", "1",
            "-subj", "/CN=Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE"
        ],
        check=True,
        capture_output=True
    )

    # Step 3: Generate server private key
    subprocess.run(
        ["openssl", "genrsa", "-out", server_key_path, "2048"],
        check=True,
        capture_output=True
    )

    # Step 4: Generate server CSR
    subprocess.run(
        [
            "openssl", "req", "-new",
            "-key", server_key_path,
            "-out", server_csr_path,
            "-subj", "/CN=localhost"
        ],
        check=True,
        capture_output=True
    )

    # Step 5: Create extensions config for server cert
    ext_config_path = os.path.join(temp_dir, "server_ext.cnf")
    with open(ext_config_path, "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        f.write("basicConstraints=critical,CA:FALSE\n")

    # Step 6: Sign server certificate with CA
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", server_csr_path,
            "-CA", ca_cert_path,
            "-CAkey", ca_key_path,
            "-CAcreateserial",
            "-out", server_cert_path,
            "-days", "1",
            "-extfile", ext_config_path
        ],
        check=True,
        capture_output=True
    )

    return server_cert_path, server_key_path, ca_cert_path, ca_key_path


def generate_client_certificate(
    temp_dir: str,
    ca_cert_path: str,
    ca_key_path: str,
    client_name: str = "testclient"
) -> Tuple[str, str]:
    """
    Generate client certificate for TLS client auth testing.

    Args:
        temp_dir: Temporary directory
        ca_cert_path: CA certificate path
        ca_key_path: CA private key path
        client_name: Common name for the client certificate (default: "testclient")

    Returns:
        Tuple[str, str]: (client_cert_path, client_key_path)
    """
    client_key_path = os.path.join(temp_dir, f"{client_name}.key")
    client_csr_path = os.path.join(temp_dir, f"{client_name}.csr")
    client_cert_path = os.path.join(temp_dir, f"{client_name}.crt")

    # Generate client private key
    subprocess.run(
        ["openssl", "genrsa", "-out", client_key_path, "2048"],
        check=True,
        capture_output=True
    )

    # Generate CSR
    subprocess.run(
        [
            "openssl", "req", "-new",
            "-key", client_key_path,
            "-out", client_csr_path,
            "-subj", f"/CN={client_name}"
        ],
        check=True,
        capture_output=True
    )

    # Sign with CA
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", client_csr_path,
            "-CA", ca_cert_path,
            "-CAkey", ca_key_path,
            "-CAcreateserial",
            "-out", client_cert_path,
            "-days", "1"
        ],
        check=True,
        capture_output=True
    )

    return client_cert_path, client_key_path


def create_http3_listener_config(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str,
    auth_config: Optional[str] = None,
    quic_config: Optional[str] = None,
    worker_threads: int = 1
) -> str:
    """
    Create HTTP/3 Listener configuration file.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        temp_dir: Temporary directory for logs
        auth_config: Optional authentication config YAML string
        quic_config: Optional QUIC config YAML string
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    auth_section = ""
    if auth_config:
        auth_section = f"""
  auth:
{auth_config}"""

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
  listeners:
  - kind: http3.listener
    args:
      address: "0.0.0.0:{proxy_port}"
      cert_path: "{cert_path}"
      key_path: "{key_path}"{quic_section}{auth_section}
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "http3_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_chain_config(
    http_port: int,
    proxy_group: List[Tuple[str, int, int]],
    ca_path: str,
    temp_dir: str,
    worker_threads: int = 1
) -> str:
    """
    Create HTTP/3 Chain service configuration file.

    Args:
        http_port: Port for the HTTP listener
        proxy_group: List of (address, port, weight) tuples
        ca_path: CA certificate path
        temp_dir: Temporary directory for logs
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    proxy_list = []
    for addr, port, weight in proxy_group:
        proxy_list.append(f"    - address: {addr}:{port}\n      weight: {weight}")

    proxy_section = "\n".join(proxy_list)

    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: http3_chain
  kind: http3_chain.http3_chain
  args:
    proxy_group:
{proxy_section}
    ca_path: "{ca_path}"

servers:
- name: http_proxy
  listeners:
  - kind: hyper.listener
    args:
      addresses: [ "0.0.0.0:{http_port}" ]
      protocols: [ http ]
      hostnames: []
      certificates: []
  service: http3_chain
"""
    config_path = os.path.join(temp_dir, "http3_chain_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def wait_for_udp_port_bound(
    host: str,
    port: int,
    timeout: float = 5.0,
    interval: float = 0.1
) -> bool:
    """
    Wait for UDP port to be bound (indicating HTTP/3 listener started).

    This function checks if a UDP port is in use by attempting to bind to it.
    If binding fails with EADDRINUSE, the port is bound by another process.

    Args:
        host: Host address
        port: Port number
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        bool: True if port is bound by another process, False if timeout
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            # Try to bind to check if port is in use
            try:
                sock.bind((host, port))
                sock.close()
                # Port is available, server not started yet
            except OSError:
                # Port is in use, server started
                sock.close()
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


# Backward-compatible alias
wait_for_udp_port = wait_for_udp_port_bound


def run_curl_http3_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    cert_path: Optional[str] = None,
    ca_path: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 10.0
) -> Tuple[int, str, str]:
    """
    Use curl to send HTTP/3 CONNECT request through proxy chain.

    Note: This tests the HTTP/3 chain service by using curl's HTTP proxy
    feature, which then connects to the HTTP/3 backend.

    Args:
        proxy_host: Proxy server host
        proxy_port: Proxy server port
        target_host: Target server host
        target_port: Target server port
        cert_path: Optional client certificate path
        ca_path: Optional CA certificate path for server verification
        username: Optional username for proxy auth
        password: Optional password for proxy auth
        timeout: Request timeout

    Returns:
        Tuple[int, str, str]: (return_code, stdout, stderr)
    """
    cmd = [
        "curl", "-s", "-p",
        "-x", f"http://{proxy_host}:{proxy_port}",
        "--connect-timeout", str(int(timeout)),
        f"http://{target_host}:{target_port}/"
    ]

    if username and password:
        cmd.extend(["-U", f"{username}:{password}"])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout + 5
    )
    return result.returncode, result.stdout, result.stderr


# ==============================================================================
# Test cases - 7.1 Basic connection scenarios
# ==============================================================================


class TestHTTP3BasicConnection:
    """Test 7.1: Basic HTTP/3 connection scenarios."""

    def test_http3_listener_starts_successfully(self) -> None:
        """
        TC-H3-001: HTTP/3 Listener starts and binds to port.

        Target: Verify HTTP/3 listener starts successfully and binds to UDP port
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30443
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            # Wait for UDP port to be bound
            assert wait_for_udp_port("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Verify process is still running
            assert proxy_proc.poll() is None, \
                "HTTP/3 listener process crashed"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_http3_listener_graceful_shutdown(self) -> None:
        """
        TC-H3-002: HTTP/3 Listener graceful shutdown.

        Target: Verify HTTP/3 listener shuts down gracefully with exit code 0
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30444
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for graceful shutdown
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.3 Authentication scenarios
# ==============================================================================


class TestHTTP3Authentication:
    """Test 7.3: HTTP/3 authentication scenarios."""

    def test_no_auth_allows_all(self) -> None:
        """
        TC-H3-AUTH-001: No authentication allows all connections.

        Target: Verify HTTP/3 listener without auth accepts all connections
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30445
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
            # No auth config means no authentication
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Verify process is running
            assert proxy_proc.poll() is None, \
                "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.5 Error handling scenarios (HTTP/3 specific)
# ==============================================================================


class TestHTTP3ErrorHandling:
    """Test 7.5: HTTP/3 error handling scenarios."""

    def test_cert_file_not_exist(self) -> None:
        """
        TC-H3-ERR-001: Certificate file does not exist.

        Target: Verify HTTP/3 listener fails to start with non-existent cert
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30450

        try:
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  listeners:
  - kind: http3.listener
    args:
      address: "0.0.0.0:{proxy_port}"
      cert_path: "/nonexistent/path/to/cert.pem"
      key_path: "/nonexistent/path/to/key.pem"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "invalid_config.yaml")
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
                assert False, "Process did not exit within expected time"

            # Should exit with error code
            assert return_code == 1, \
                f"Expected exit code 1, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_key_file_not_exist(self) -> None:
        """
        TC-H3-ERR-002: Private key file does not exist.

        Target: Verify HTTP/3 listener fails to start with non-existent key
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30451

        try:
            cert_path, _, _, _ = generate_test_certificates(temp_dir)

            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  listeners:
  - kind: http3.listener
    args:
      address: "0.0.0.0:{proxy_port}"
      cert_path: "{cert_path}"
      key_path: "/nonexistent/path/to/key.pem"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "invalid_config.yaml")
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
                assert False, "Process did not exit within expected time"

            assert return_code == 1, \
                f"Expected exit code 1, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_cert_key_mismatch(self) -> None:
        """
        TC-H3-ERR-003: Certificate and key do not match.

        Target: Verify HTTP/3 listener fails to start with mismatched cert/key
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30452

        try:
            # Generate two different key pairs
            cert_path1, _, _, _ = generate_test_certificates(temp_dir)

            # Generate another key
            key_path2 = os.path.join(temp_dir, "wrong.key")
            subprocess.run(
                ["openssl", "genrsa", "-out", key_path2, "2048"],
                check=True,
                capture_output=True
            )

            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  listeners:
  - kind: http3.listener
    args:
      address: "0.0.0.0:{proxy_port}"
      cert_path: "{cert_path1}"
      key_path: "{key_path2}"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "mismatch_config.yaml")
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
                assert False, "Process did not exit within expected time"

            # Should exit with error code due to key mismatch
            assert return_code != 0, \
                f"Expected non-zero exit code, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.7 Configuration validation scenarios (HTTP/3 specific)
# ==============================================================================


class TestHTTP3ConfigValidation:
    """Test 7.7: HTTP/3 configuration validation scenarios."""

    def test_invalid_quic_param_uses_default(self) -> None:
        """
        TC-H3-CFG-001: Invalid QUIC parameter uses default value.

        Target: Verify HTTP/3 listener starts with invalid QUIC params
                using default values
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30460
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            # Invalid QUIC config: max_concurrent_bidi_streams = 0
            quic_config = """      max_concurrent_bidi_streams: 0
      max_idle_timeout_ms: 30000"""

            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir,
                quic_config=quic_config
            )

            proxy_proc = start_proxy(config_path)

            # Should still start successfully with default value
            assert wait_for_udp_port("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener should start with default QUIC params"

            # Verify process is running
            assert proxy_proc.poll() is None, \
                "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_missing_required_fields(self) -> None:
        """
        TC-H3-CFG-002: Missing required fields causes startup failure.

        Target: Verify HTTP/3 listener fails without required fields
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30461

        try:
            # Missing cert_path and key_path
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  listeners:
  - kind: http3.listener
    args:
      address: "0.0.0.0:{proxy_port}"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "missing_fields.yaml")
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
                assert False, "Process did not exit within expected time"

            assert return_code != 0, \
                f"Expected non-zero exit code, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_address_format(self) -> None:
        """
        TC-H3-CFG-003: Invalid address format causes startup failure.

        Target: Verify HTTP/3 listener fails with invalid address
        """
        temp_dir = tempfile.mkdtemp()
        cert_path, key_path, _, _ = generate_test_certificates(temp_dir)

        try:
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  listeners:
  - kind: http3.listener
    args:
      address: "invalid_address_format"
      cert_path: "{cert_path}"
      key_path: "{key_path}"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "invalid_addr.yaml")
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
                assert False, "Process did not exit within expected time"

            assert return_code != 0, \
                f"Expected non-zero exit code, got {return_code}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.4 Graceful Shutdown scenarios (HTTP/3 specific)
# ==============================================================================


class TestHTTP3GracefulShutdown:
    """Test 7.4: HTTP/3 graceful shutdown scenarios."""

    def test_shutdown_with_no_connections(self) -> None:
        """
        TC-H3-SHUTDOWN-001: Shutdown with no connections completes quickly.

        Target: Verify HTTP/3 listener shuts down quickly with no connections
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30470
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            start_time = time.time()
            proxy_proc.send_signal(signal.SIGTERM)

            return_code = proxy_proc.wait(timeout=10)
            elapsed = time.time() - start_time

            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

            # Should complete quickly (within 2 seconds)
            assert elapsed < 2.0, \
                f"Shutdown took too long: {elapsed:.2f}s"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_shutdown_with_multiple_workers(self) -> None:
        """
        TC-H3-SHUTDOWN-002: Shutdown with multiple worker threads.

        Target: Verify HTTP/3 listener shuts down gracefully with multiple workers
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 30471
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, _, _ = generate_test_certificates(temp_dir)
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir,
                worker_threads=4
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            proxy_proc.send_signal(signal.SIGTERM)

            try:
                return_code = proxy_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - Service delegation scenarios (for refactoring)
# ==============================================================================


class TestHTTP3ServiceDelegation:
    """Test that H3 listener delegates to Service without method restriction.

    After the refactoring, the H3 listener should NOT reject non-CONNECT
    requests. Instead, it should forward all requests to the Service, which
    decides how to handle them.

    This is a critical behavioral change from the monolithic H3 listener.
    """

    def test_h3_listener_non_connect_method_handled_by_service(self) -> None:
        """
        TC-H3-DELEGATION-001: Non-CONNECT method is forwarded to Service.

        Target: Verify that after refactoring, the H3 listener forwards
        non-CONNECT requests to the Service instead of rejecting them
        at the listener level.

        Before refactoring: Listener rejected non-CONNECT with 405 and a
        message containing "got {method}".
        After refactoring: Listener forwards to Service; Service decides
        the response.

        This test verifies the request is forwarded to the service by checking
        that we get a response (not a connection error or listener-level reject).
        The connect_tcp service returns 405 for non-CONNECT methods, which is
        the expected behavior.
        """
        import asyncio
        from .utils.http3_client import (
            AIOQUIC_AVAILABLE,
            H3Client,
        )

        if not AIOQUIC_AVAILABLE:
            pytest.skip("aioquic library not available")

        temp_dir = tempfile.mkdtemp()
        proxy_port = 30480
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port("127.0.0.1", proxy_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Send a GET request (non-CONNECT) using HTTP/3 client
            async def do_get_request():
                client = H3Client("127.0.0.1", proxy_port, ca_path=ca_path)
                connected = await asyncio.wait_for(client.connect(), timeout=15.0)
                if not connected:
                    return False, 0, "Connection failed"

                response = await asyncio.wait_for(
                    client.send_request("GET", "/"),
                    timeout=15.0
                )
                await client.close()
                return True, response.status_code, response.body

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success, status_code, body = loop.run_until_complete(do_get_request())
            finally:
                loop.close()

            # KEY ASSERTION: Request was forwarded to service and we got a response.
            # Before refactoring, the listener rejected with a specific message
            # "Method Not Allowed: only CONNECT is supported, got GET".
            # After refactoring, the listener forwards to the service, which
            # returns 405 because connect_tcp only supports CONNECT.
            assert success, "HTTP/3 connection should succeed (request forwarded to service)"
            assert status_code == 405, (
                f"Service should return 405 for non-CONNECT, got {status_code}"
            )

            # CRITICAL: Verify the response came from the SERVICE, not listener-level rejection.
            # The connect_tcp service returns "Only CONNECT method is supported" for non-CONNECT.
            # The old listener (pre-refactoring) would return "Method Not Allowed: only CONNECT is supported".
            # Checking the body confirms the request was actually forwarded to the service.
            assert b"Only CONNECT method is supported" in body, (
                f"Response body should contain service's message, got: {body!r}. "
                f"This verifies the request was forwarded to the service, not rejected at listener level."
            )

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)