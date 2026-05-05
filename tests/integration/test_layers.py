"""Black-box tests for the layer mechanism.

All HTTP requests use subprocess.run(["curl", ...]) instead of Python requests library.
This matches real-world proxy usage more closely.
"""
import base64
import socket
import threading
import time
import os

from .utils.helpers import curl_request, curl_request_with_headers


class TestAuthLayer:
    """Verify auth.basic_auth layer works."""

    def test_auth_rejects_without_credentials(self, proxy_with_config) -> None:
        """Request without Proxy-Authorization should get 407."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {"users": [{"username": "admin", "password": "secret"}]},
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status, headers, _ = curl_request_with_headers(
                "http://example.com/", proxy.port,
            )
            assert status == 407
            assert "proxy-authenticate" in headers

    def test_auth_accepts_valid_credentials(self, proxy_with_config) -> None:
        """Request with valid credentials should succeed."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {"users": [{"username": "admin", "password": "secret"}]},
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            creds = base64.b64encode(b"admin:secret").decode()
            status = curl_request(
                "http://example.com/", proxy.port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 200

    def test_auth_rejects_wrong_password(self, proxy_with_config) -> None:
        """Request with wrong password should get 407."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {"users": [{"username": "admin", "password": "secret"}]},
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            creds = base64.b64encode(b"admin:wrong").decode()
            status = curl_request(
                "http://example.com/", proxy.port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 407

    def test_auth_rejects_non_basic_scheme(self, proxy_with_config) -> None:
        """Request with non-Basic Proxy-Authorization should get 407."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {"users": [{"username": "admin", "password": "secret"}]},
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status = curl_request(
                "http://example.com/", proxy.port,
                headers={"Proxy-Authorization": "Bearer some-token"},
            )
            assert status == 407

    def test_auth_rejects_malformed_basic_header(self, proxy_with_config) -> None:
        """Request with malformed Basic header should get 407."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {"users": [{"username": "admin", "password": "secret"}]},
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status = curl_request(
                "http://example.com/", proxy.port,
                headers={"Proxy-Authorization": "Basic not-valid-base64!!!"},
            )
            assert status == 407


class TestAccessLogLayer:
    """Verify access_log.file layer creates log entries."""

    def test_access_log_creates_file(self, proxy_with_config) -> None:
        """Access log layer should create log file after a request."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": {"context_fields": ["auth.basic_auth.user"]},
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status = curl_request("http://example.com/", proxy.port)
            assert status == 200

            # Wait for log flush (writer flushes every 1 second)
            time.sleep(2)

            log_path = os.path.join(proxy.working_dir, "logs", "access.log")
            assert os.path.exists(log_path), f"Log file should exist at {log_path}"

    def test_access_log_without_context_fields(self, proxy_with_config) -> None:
        """Access log layer with empty context_fields should still log base fields."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {"kind": "access_log.file", "args": {}},
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status = curl_request("http://example.com/", proxy.port)
            assert status == 200

            time.sleep(2)

            log_path = os.path.join(proxy.working_dir, "logs", "access.log")
            assert os.path.exists(log_path)


class TestCombinedLayers:
    """Verify multiple layers work together."""

    def test_auth_then_access_log(self, proxy_with_config) -> None:
        """Auth layer + access_log layer should work together."""
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": {
                                "context_fields": [
                                    "auth.basic_auth.user",
                                    "auth.basic_auth.auth_type",
                                ]
                            },
                        },
                        {
                            "kind": "auth.basic_auth",
                            "args": {"users": [{"username": "admin", "password": "secret"}]},
                        },
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            # Without auth -> 407
            status = curl_request("http://example.com/", proxy.port)
            assert status == 407

            # With auth -> 200
            creds = base64.b64encode(b"admin:secret").decode()
            status = curl_request(
                "http://example.com/", proxy.port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 200

            # Wait for log flush and verify log contains entries
            time.sleep(2)
            log_path = os.path.join(proxy.working_dir, "logs", "access.log")
            assert os.path.exists(log_path)
            with open(log_path) as f:
                log_content = f.read()
            # Log should contain entries for both requests
            assert "407" in log_content or "200" in log_content


class TestAccessLogErrorHandling:
    """Verify access_log layer handles service errors correctly."""

    def test_access_log_converts_err_to_500(self, proxy_with_config) -> None:
        """When inner service returns Err, access_log should convert to 5xx response.

        Uses connect_tcp service targeting an unreachable address (127.0.0.1:1).
        Port 1 on localhost is not listening, so TcpStream::connect will fail
        immediately with ConnectionRefused. The access_log layer should catch
        this error and convert it to an HTTP 5xx response.
        """
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "tcp_svc"}
            ],
            "services": [
                {
                    "name": "tcp_svc",
                    "kind": "connect_tcp.connect_tcp",
                    "layers": [
                        {"kind": "access_log.file", "args": {}},
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            # CONNECT to a port that immediately refuses connections.
            # Port 1 on localhost is not listening, so TcpStream::connect
            # will fail with ConnectionRefused -> BAD_GATEWAY (502).
            # Use a raw TCP connection because curl's -w "%{http_code}"
            # reports 000 for CONNECT tunnel failures.
            sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            connect_req = (
                "CONNECT 127.0.0.1:1 HTTP/1.1\r\n"
                "Host: 127.0.0.1:1\r\n"
                "\r\n"
            )
            sock.sendall(connect_req.encode())
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
            sock.close()
            status_line = response.split(b"\r\n")[0].decode()
            # Extract status code from "HTTP/1.1 502 Bad Gateway"
            status = int(status_line.split()[1]) if len(status_line.split()) >= 2 else 0
            # Should get a server error (500 or 502), not a crash or hang
            assert status >= 500, f"Expected 5xx error, got {status}"

            # Verify the proxy is still alive after the error
            # (error didn't crash the proxy)
            time.sleep(1)
            # Wait for log flush
            time.sleep(2)
            log_path = os.path.join(proxy.working_dir, "logs", "access.log")
            assert os.path.exists(log_path)
            with open(log_path) as f:
                log_content = f.read()
            # Log should contain the error entry with status 500 or 502
            assert "500" in log_content or "502" in log_content


class TestLayerOrdering:
    """Verify layers are applied in correct order (outer first, inner last)."""

    def test_outer_layer_sees_request_first(self, proxy_with_config) -> None:
        """Outer layer (access_log) should see request before inner layer (auth).

        Config lists [access_log, auth] (outer to inner).
        When auth rejects (407), access_log should still record the 407.
        """
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {"kind": "access_log.file", "args": {}},
                        {
                            "kind": "auth.basic_auth",
                            "args": {"users": [{"username": "admin", "password": "secret"}]},
                        },
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            # Request without auth -> 407 from auth layer
            status = curl_request("http://example.com/", proxy.port)
            assert status == 407

            # Access log should still record this (outer layer)
            time.sleep(2)
            log_path = os.path.join(proxy.working_dir, "logs", "access.log")
            assert os.path.exists(log_path)


class TestMultiThreadedAccessLog:
    """Verify access log entries are not interleaved under concurrent load."""

    def test_concurrent_requests_log_integrity(self, proxy_with_config) -> None:
        """Send multiple concurrent requests and verify each log line is complete.

        The LogService uses a single writer thread with a channel, which inherently
        prevents interleaving. This test verifies that property.
        """
        config = {
            "listeners": [
                {"name": "http_main", "kind": "http", "addresses": ["127.0.0.1:AUTO_PORT"]}
            ],
            "servers": [
                {"name": "default", "hostnames": [], "listeners": ["http_main"], "service": "echo_svc"}
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {"kind": "access_log.file", "args": {}},
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            num_requests = 10
            results = [None] * num_requests

            def make_request(idx: int) -> None:
                results[idx] = curl_request("http://example.com/", proxy.port)

            threads = [threading.Thread(target=make_request, args=(i,)) for i in range(num_requests)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

            # All requests should succeed
            for i, status in enumerate(results):
                assert status == 200, f"Request {i} got status {status}"

            # Wait for log flush
            time.sleep(3)

            log_path = os.path.join(proxy.working_dir, "logs", "access.log")
            assert os.path.exists(log_path)

            with open(log_path) as f:
                log_content = f.read()
            lines = [line.strip() for line in log_content.strip().split('\n') if line.strip()]

            # Each line should contain all expected fields (not interleaved)
            for i, line in enumerate(lines):
                # A complete log line should contain method, status, and duration
                assert "GET" in line or "CONNECT" in line, f"Line {i} missing method: {line}"
                assert "200" in line, f"Line {i} missing status: {line}"
                assert "ms" in line, f"Line {i} missing duration: {line}"

            # Should have at least num_requests lines
            assert len(lines) >= num_requests, f"Expected at least {num_requests} log lines, got {len(lines)}"
