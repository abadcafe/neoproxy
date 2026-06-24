"""Black-box tests for the layer mechanism.

All HTTP requests use subprocess.run(["curl", ...]) instead of Python requests library.
This matches real-world proxy usage more closely.
"""

import base64
import glob
import os
import socket
import threading
import time

from .types import (
    ConfigDict,
    ProxyWithConfig,
)
from .utils.helpers import curl_request, curl_request_with_headers


def _find_access_log(log_dir: str, prefix: str = "access") -> str | None:
    """Find the first access log file matching the prefix in the log directory.

    With rotate_daily=true (default), the file is named '{prefix}.{date}'.
    With rotate_daily=false, the file is named '{prefix}' (no extension).

    Returns:
        Path to the log file, or None if not found.
    """
    if not os.path.isdir(log_dir):
        return None
    # Try exact prefix match first (rotate_daily=false: logs/access)
    exact = os.path.join(log_dir, prefix)
    if os.path.isfile(exact):
        return exact
    # Try glob for date-suffixed files (rotate_daily=true: logs/access.2026-05-10)
    matches = sorted(glob.glob(os.path.join(log_dir, f"{prefix}.*")))
    for m in matches:
        if os.path.isfile(m):
            return m
    return None


def wait_for_log_file(
    log_dir: str,
    prefix: str = "access",
    timeout: float = 2.0,
    contains: str | None = None,
) -> bool:
    """Poll for log file to exist (and optionally contain specific text).

    Args:
        log_dir: Directory to search for the log file.
        prefix: File name prefix (default: "access").
        timeout: Maximum wait time in seconds.
        contains: Optional text to search for in the file.

    Returns:
        True if the log file exists (and contains the text if specified).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        log_path = _find_access_log(log_dir, prefix)
        if log_path is not None:
            if contains is None:
                return True
            with open(log_path) as f:
                if contains in f.read():
                    return True
        time.sleep(0.05)
    log_path = _find_access_log(log_dir, prefix)
    if log_path is None:
        return False
    if contains is None:
        return True
    with open(log_path) as f:
        return contains in f.read()


def _access_log_layer_args(
    writer: str = "logs/access",
    context_fields: list[str] | None = None,
) -> ConfigDict:
    """Build access_log.file layer args with the required writer field."""
    args: ConfigDict = {"writer": writer}
    if context_fields:
        args["context_fields"] = [field for field in context_fields]
    return args


def _access_log_plugins(writer: str = "logs/access") -> ConfigDict:
    """Build plugins dict with echo and access_log writer definition."""
    return {
        "echo": None,
        "access_log": {
            "writers": [{"path_prefix": writer}],
        },
    }


class TestAuthLayer:
    """Verify auth.basic_auth layer works."""

    def test_auth_rejects_without_credentials(self, proxy_with_config: ProxyWithConfig) -> None:
        """Request without Proxy-Authorization should get 407."""
        config: ConfigDict = {
            "plugins": {"echo": None, "auth": None},
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {
                                        "username": "admin",
                                        "password": "secret",
                                    }
                                ]
                            },
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status, headers, _ = curl_request_with_headers(
                "http://example.com/",
                proxy.port,
            )
            assert status == 407
            assert "proxy-authenticate" in headers

    def test_auth_accepts_valid_credentials(self, proxy_with_config: ProxyWithConfig) -> None:
        """Request with valid credentials should succeed."""
        config: ConfigDict = {
            "plugins": {"echo": None, "auth": None},
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {
                                        "username": "admin",
                                        "password": "secret",
                                    }
                                ]
                            },
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            creds = base64.b64encode(b"admin:secret").decode()
            status = curl_request(
                "http://example.com/",
                proxy.port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 200

    def test_auth_rejects_wrong_password(self, proxy_with_config: ProxyWithConfig) -> None:
        """Request with wrong password should get 407."""
        config: ConfigDict = {
            "plugins": {"echo": None, "auth": None},
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {
                                        "username": "admin",
                                        "password": "secret",
                                    }
                                ]
                            },
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            creds = base64.b64encode(b"admin:wrong").decode()
            status = curl_request(
                "http://example.com/",
                proxy.port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 407

    def test_auth_rejects_non_basic_scheme(self, proxy_with_config: ProxyWithConfig) -> None:
        """Request with non-Basic Proxy-Authorization should get 407."""
        config: ConfigDict = {
            "plugins": {"echo": None, "auth": None},
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {
                                        "username": "admin",
                                        "password": "secret",
                                    }
                                ]
                            },
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status = curl_request(
                "http://example.com/",
                proxy.port,
                headers={"Proxy-Authorization": "Bearer some-token"},
            )
            assert status == 407

    def test_auth_rejects_malformed_basic_header(self, proxy_with_config: ProxyWithConfig) -> None:
        """Request with malformed Basic header should get 407."""
        config: ConfigDict = {
            "plugins": {"echo": None, "auth": None},
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {
                                        "username": "admin",
                                        "password": "secret",
                                    }
                                ]
                            },
                        }
                    ],
                }
            ],
        }

        with proxy_with_config(config) as proxy:
            status = curl_request(
                "http://example.com/",
                proxy.port,
                headers={"Proxy-Authorization": "Basic not-valid-base64!!!"},
            )
            assert status == 407


class TestAccessLogLayer:
    """Verify access_log.file layer creates log entries."""

    def test_access_log_creates_file(self, proxy_with_config: ProxyWithConfig) -> None:
        """Access log layer should create log file after a request."""
        config: ConfigDict = {
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": _access_log_layer_args(
                                context_fields=["basic_auth.user"],
                            ),
                        }
                    ],
                }
            ],
            "plugins": _access_log_plugins(),
        }

        with proxy_with_config(config) as proxy:
            status = curl_request("http://example.com/", proxy.port)
            assert status == 200

            # Poll for log file to be written
            log_dir = os.path.join(proxy.working_dir, "logs")
            assert wait_for_log_file(log_dir), f"Log file should exist in {log_dir}"

    def test_access_log_without_context_fields(self, proxy_with_config: ProxyWithConfig) -> None:
        """Access log layer with empty context_fields should still log base fields."""
        config: ConfigDict = {
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": _access_log_layer_args(),
                        },
                    ],
                }
            ],
            "plugins": _access_log_plugins(),
        }

        with proxy_with_config(config) as proxy:
            status = curl_request("http://example.com/", proxy.port)
            assert status == 200

            log_dir = os.path.join(proxy.working_dir, "logs")
            assert wait_for_log_file(log_dir), f"Log file should exist in {log_dir}"


class TestCombinedLayers:
    """Verify multiple layers work together."""

    def test_auth_then_access_log(self, proxy_with_config: ProxyWithConfig) -> None:
        """Auth layer + access_log layer should work together."""
        config: ConfigDict = {
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": _access_log_layer_args(
                                context_fields=[
                                    "basic_auth.user",
                                    "basic_auth.auth_type",
                                ],
                            ),
                        },
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {
                                        "username": "admin",
                                        "password": "secret",
                                    }
                                ]
                            },
                        },
                    ],
                }
            ],
            "plugins": {**_access_log_plugins(), "auth": None},
        }

        with proxy_with_config(config) as proxy:
            # Without auth -> 407
            status = curl_request("http://example.com/", proxy.port)
            assert status == 407

            # With auth -> 200
            creds = base64.b64encode(b"admin:secret").decode()
            status = curl_request(
                "http://example.com/",
                proxy.port,
                headers={"Proxy-Authorization": f"Basic {creds}"},
            )
            assert status == 200

            # Wait for log file to contain entries
            log_dir = os.path.join(proxy.working_dir, "logs")
            # Wait for either 407 or 200 to appear in log
            assert wait_for_log_file(log_dir, contains="407") or wait_for_log_file(log_dir, contains="200"), (
                "Log should contain request entries"
            )


class TestAccessLogErrorHandling:
    """Verify access_log layer handles service errors correctly."""

    def test_access_log_converts_err_to_500(self, proxy_with_config: ProxyWithConfig) -> None:
        """When inner service returns Err, access_log should convert to 5xx response.

        Uses connect_tcp service targeting an unreachable address (127.0.0.1:1).
        Port 1 on localhost is not listening, so TcpStream::connect will fail
        immediately with ConnectionRefused. The access_log layer should catch
        this error and convert it to an HTTP 5xx response.
        """
        config: ConfigDict = {
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "tcp_svc",
                }
            ],
            "services": [
                {
                    "name": "tcp_svc",
                    "kind": "http_upstream.upstream",
                    "args": {"upstream": "direct"},
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": _access_log_layer_args(),
                        },
                    ],
                }
            ],
            "plugins": {
                **_access_log_plugins(),
                "http_upstream": {
                    "upstreams": [{"name": "direct"}],
                },
            },
        }

        with proxy_with_config(config) as proxy:
            # CONNECT to a port that immediately refuses connections.
            # Port 1 on localhost is not listening, so TcpStream::connect
            # will fail with ConnectionRefused -> BAD_GATEWAY (502).
            # Use a raw TCP connection because curl's -w "%{http_code}"
            # reports 000 for CONNECT tunnel failures.
            sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            connect_req = "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
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
            assert proxy.process.poll() is None, "Proxy should still be running"

            # Wait for log file to contain error entry
            log_dir = os.path.join(proxy.working_dir, "logs")
            assert wait_for_log_file(log_dir, contains=str(status)), f"Log should contain status {status}"


class TestLayerOrdering:
    """Verify layers are applied in correct order (outer first, inner last)."""

    def test_outer_layer_sees_request_first(self, proxy_with_config: ProxyWithConfig) -> None:
        """Outer layer (access_log) should see request before inner layer (auth).

        Config lists [access_log, auth] (outer to inner).
        When auth rejects (407), access_log should still record the 407.
        """
        config: ConfigDict = {
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": _access_log_layer_args(),
                        },
                        {
                            "kind": "auth.basic_auth",
                            "args": {
                                "users": [
                                    {
                                        "username": "admin",
                                        "password": "secret",
                                    }
                                ]
                            },
                        },
                    ],
                }
            ],
            "plugins": {**_access_log_plugins(), "auth": None},
        }

        with proxy_with_config(config) as proxy:
            # Request without auth -> 407 from auth layer
            status = curl_request("http://example.com/", proxy.port)
            assert status == 407

            # Access log should still record this (outer layer)
            log_dir = os.path.join(proxy.working_dir, "logs")
            assert wait_for_log_file(log_dir, contains="407"), "Log should contain 407 status"


class TestMultiThreadedAccessLog:
    """Verify access log entries are not interleaved under concurrent load."""

    def test_concurrent_requests_log_integrity(self, proxy_with_config: ProxyWithConfig) -> None:
        """Send multiple concurrent requests and verify each log line is complete.

        The LogService uses a single writer thread with a channel, which inherently
        prevents interleaving. This test verifies that property.
        """
        config: ConfigDict = {
            "listeners": [
                {
                    "name": "http_main",
                    "kind": "http",
                    "addresses": ["127.0.0.1:AUTO_PORT"],
                }
            ],
            "servers": [
                {
                    "name": "default",
                    "hostnames": [],
                    "listeners": ["http_main"],
                    "service": "echo_svc",
                }
            ],
            "services": [
                {
                    "name": "echo_svc",
                    "kind": "echo.echo",
                    "layers": [
                        {
                            "kind": "access_log.file",
                            "args": _access_log_layer_args(),
                        },
                    ],
                }
            ],
            "plugins": _access_log_plugins(),
        }

        with proxy_with_config(config) as proxy:
            num_requests = 10
            results: list[int | None] = [None] * num_requests

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

            # Poll for log file with enough lines
            log_dir = os.path.join(proxy.working_dir, "logs")
            deadline = time.time() + 3.0
            lines: list[str] = []
            while time.time() < deadline:
                log_path = _find_access_log(log_dir)
                if log_path is not None and os.path.exists(log_path):
                    with open(log_path) as f:
                        log_content = f.read()
                    lines = [line.strip() for line in log_content.strip().split("\n") if line.strip()]
                    if len(lines) >= num_requests:
                        break
                time.sleep(0.1)

            # Each line should contain all expected fields (not interleaved)
            for i, line in enumerate(lines):
                # A complete log line should contain method, status, and duration
                assert "GET" in line or "CONNECT" in line, f"Line {i} missing method: {line}"
                assert "200" in line, f"Line {i} missing status: {line}"
                assert "ms" in line, f"Line {i} missing duration: {line}"

            # Should have at least num_requests lines
            assert len(lines) >= num_requests, f"Expected at least {num_requests} log lines, got {len(lines)}"
