"""HTTP/HTTPS missing-Host rejection through the process interface.

Certificate admission for CONNECT and forward requests lives in
test_chain_matrix_auth.py; this module retains the distinct wire-header contract.
"""

import os
import shutil
import subprocess
import tempfile

import pytest
import yaml

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import ConfigDict, StringMap
from tests.fixtures.notified_process import ProxyProcess
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, terminate_process


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

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not proc.wait_ready(timeout=5.0):
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

            proc = ProxyProcess(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not proc.wait_ready(timeout=5.0):
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
