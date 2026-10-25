"""transport identity process integration tests."""

import os
import shutil
import subprocess
import tempfile

import pytest
import yaml

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import ConfigDict, StringMap
from tests.fixtures.ports import (
    get_unique_port,
    wait_for_proxy,
    wait_for_udp_port_bound,
)
from tests.fixtures.proxy_process import BytesProcess, terminate_process


class TestHTTPSClientCert:
    """Test HTTPS listener client certificate verification (Plan B).

    TLS verifies any presented client certificate against the listener's
    combined CA roots. allow_unauthenticated() permits omitting a certificate,
    not presenting an invalid one. Routing only checks whether a certificate
    is required: 403 if the selected server requires one and none was supplied.
    """

    def test_https_no_cert_returns_403(self, shared_test_certs: StringMap) -> None:
        """
        Test that HTTPS server with client_ca_certs returns 403 when
        client does not present a certificate.

        Plan B: TLS handshake succeeds, HTTP layer enforces cert requirement.
        """
        import socket
        import ssl

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_https_mtls_")
        https_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "https_main",
                        "kind": "https",
                        "addresses": [f"127.0.0.1:{https_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "mtls_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ],
                            "client_ca_certs": [ca_path],
                        },
                        "listeners": ["https_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTPS listener failed to start within timeout")

            # Connect WITHOUT client certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
            ssl_sock.connect(("127.0.0.1", https_port))

            # Send request - should get 403 Forbidden
            ssl_sock.sendall(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = ssl_sock.recv(4096).decode()
            ssl_sock.close()

            assert "403" in response, (
                "Expected 403 Forbidden for missing "
                + f"client certificate, got: {response}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_https_with_cert_returns_200(
        self, shared_test_certs: StringMap, shared_client_cert: StringMap
    ) -> None:
        """
        Test that HTTPS server with client_ca_certs returns 200 when
        client presents a valid certificate.
        """
        import socket
        import ssl

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_https_mtls_ok_")
        https_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            client_cert_path = shared_client_cert["client_cert_path"]
            client_key_path = shared_client_cert["client_key_path"]

            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "https_main",
                        "kind": "https",
                        "addresses": [f"127.0.0.1:{https_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "mtls_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ],
                            "client_ca_certs": [ca_path],
                        },
                        "listeners": ["https_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTPS listener failed to start within timeout")

            # Connect WITH valid client certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.load_cert_chain(
                certfile=client_cert_path,
                keyfile=client_key_path,
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
            ssl_sock.connect(("127.0.0.1", https_port))

            # Send request - should succeed
            ssl_sock.sendall(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = ssl_sock.recv(4096).decode()
            ssl_sock.close()

            # Should get 200 OK (or 407 if auth is also configured)
            assert "200" in response or "407" in response, (
                f"Expected 200 or 407 with valid client cert, got: {response}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3ClientCert:
    """Test HTTP/3 listener client certificate verification (Plan B).

    TLS verifies any presented client certificate against the listener's
    combined CA roots. allow_unauthenticated() permits omitting a certificate,
    not presenting an invalid one. Routing only checks whether a certificate
    is required: 403 if the selected server requires one and none was supplied.
    """

    def test_h3_no_cert_returns_403(self, shared_test_certs: StringMap) -> None:
        """
        Test that HTTP/3 server with client_ca_certs returns 403 when
        client does not present a certificate.
        """
        import asyncio

        from tests.fixtures.http3_client import perform_h3_connection_test

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_h3_mtls_")
        http3_port = get_unique_port()
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "h3_main",
                        "kind": "http3",
                        "addresses": [f"127.0.0.1:{http3_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "mtls_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ],
                            "client_ca_certs": [ca_path],
                        },
                        "listeners": ["h3_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_udp_port_bound("127.0.0.1", http3_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP/3 listener failed to start within timeout")

            # Connect WITHOUT client certificate
            success, status_code, message = asyncio.run(
                perform_h3_connection_test(
                    "127.0.0.1",
                    http3_port,
                    ca_path=ca_path,
                    timeout=15.0,
                )
            )

            # Plan B: TLS handshake succeeds, HTTP layer returns 403
            assert success, (
                f"TLS handshake should succeed without client cert. Message: {message}"
            )
            assert status_code == 403, (
                "Expected 403 Forbidden for missing client certificate, got"
                + f" {status_code}. Message: {message}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestHostHeaderRequired:
    """Test that Host header is required for HTTP/HTTPS listeners."""

    def test_http_missing_host_returns_400(self) -> None:
        """
        Test that HTTP request without Host header returns 400.

        Per the listener consistency checks, the Host header MUST
        exist for all requests on HTTP listeners.
        """
        http_port = get_unique_port()

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_host_req_")
        proc: BytesProcess | None = None

        try:
            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "http_main",
                        "kind": "http",
                        "addresses": [f"127.0.0.1:{http_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "default_server",
                        "listeners": ["http_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", http_port, timeout=5.0, proc=proc):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTP listener failed to start within timeout")

            # Send GET request WITHOUT Host header
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(("127.0.0.1", http_port))
            sock.sendall(b"GET /test HTTP/1.1\r\n\r\n")
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            assert b"400" in response, (
                "Expected 400 Bad Request for missing Host header, got:"
                + f" {response.decode(errors='replace')[:200]}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_https_missing_host_returns_400(self, shared_test_certs: StringMap) -> None:
        """
        Test that HTTPS request without Host header returns 400.

        Per the listener consistency checks, the Host header MUST
        exist for all requests on HTTPS listeners.
        """
        import socket
        import ssl

        https_port = get_unique_port()

        temp_dir = tempfile.mkdtemp(prefix="neoproxy_https_host_req_")
        proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]

            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"echo": None},
                "services": [
                    {
                        "name": "echo",
                        "kind": "echo.echo",
                        "args": {},
                    }
                ],
                "listeners": [
                    {
                        "name": "https_main",
                        "kind": "https",
                        "addresses": [f"127.0.0.1:{https_port}"],
                    }
                ],
                "servers": [
                    {
                        "name": "default_server",
                        "tls": {
                            "certificates": [
                                {
                                    "cert_path": cert_path,
                                    "key_path": key_path,
                                }
                            ]
                        },
                        "listeners": ["https_main"],
                        "service": "echo",
                    }
                ],
            }

            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_for_proxy("127.0.0.1", https_port, timeout=5.0):
                if proc.poll() is not None:
                    _, stderr_data = proc.communicate(timeout=5)
                    stderr_text = stderr_data.decode("utf-8", errors="replace")
                    pytest.fail(f"Process failed to start.\nstderr: {stderr_text}")
                pytest.fail("HTTPS listener failed to start within timeout")

            # Send GET request WITHOUT Host header over TLS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            ssl_sock = context.wrap_socket(sock, server_hostname="localhost")
            ssl_sock.connect(("127.0.0.1", https_port))
            ssl_sock.sendall(b"GET /test HTTP/1.1\r\n\r\n")
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            ssl_sock.close()

            assert b"400" in response, (
                "Expected 400 Bad Request for missing Host header, got:"
                + f" {response.decode(errors='replace')[:200]}"
            )

        finally:
            if proc and proc.poll() is None:
                terminate_process(proc)
            shutil.rmtree(temp_dir, ignore_errors=True)
