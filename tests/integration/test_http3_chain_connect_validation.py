"""
HTTP/3 Chain CONNECT method validation integration tests.

Test target: Verify http3_chain service returns correct HTTP error responses
for non-CONNECT requests and invalid CONNECT targets.

Test nature: Black-box testing through external interface (HTTP)

Expected behavior after fix:
- Non-CONNECT method (e.g. GET) -> 405 Method Not Allowed
- CONNECT with missing port -> 400 Bad Request
- CONNECT with port zero -> 400 Bad Request
- CONNECT with no authority -> 400 Bad Request
"""

import subprocess
import tempfile
import shutil
import re
from typing import Optional, Tuple, Generator
from contextlib import contextmanager

from .utils.helpers import (
    start_proxy,
    wait_for_proxy,
    send_raw_request,
    terminate_process,
)

from .test_http3_listener import (
    generate_test_certificates,
    create_http3_chain_config,
)


def parse_http_response(response: bytes) -> Tuple[int, str, dict, bytes]:
    """
    Parse raw HTTP response into components.

    Args:
        response: Raw HTTP response bytes

    Returns:
        Tuple of (status_code, status_text, headers_dict, body)
    """
    try:
        if b"\r\n\r\n" in response:
            header_part, body = response.split(b"\r\n\r\n", 1)
        else:
            header_part = response
            body = b""

        lines = header_part.decode("utf-8", errors="ignore").split("\r\n")
        status_line = lines[0] if lines else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)\s*(.*)", status_line)
        if status_match:
            status_code = int(status_match.group(1))
            status_text = status_match.group(2).strip()
        else:
            status_code = 0
            status_text = ""

        headers: dict = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        return status_code, status_text, headers, body
    except Exception:
        return 0, "", {}, response


@contextmanager
def chain_service_context(
    http_port: int,
    h3_port: int
) -> Generator[Tuple[str, subprocess.Popen], None, None]:
    """
    Context manager for http3_chain service setup and teardown.

    Creates a temporary directory, generates certificates, creates config,
    starts the proxy, and ensures cleanup on exit.

    Args:
        http_port: Port for the HTTP listener
        h3_port: Port for the (non-existent) H3 upstream

    Yields:
        Tuple[str, subprocess.Popen]: (temp_dir, proxy_process)
    """
    temp_dir = tempfile.mkdtemp()
    proxy_proc: Optional[subprocess.Popen] = None

    try:
        _, _, ca_path, _ = generate_test_certificates(temp_dir)
        config_path = create_http3_chain_config(
            http_port=http_port,
            proxy_group=[("127.0.0.1", h3_port, 1)],
            ca_path=ca_path,
            temp_dir=temp_dir,
        )
        proxy_proc = start_proxy(config_path)
        assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
            "HTTP listener failed to start"

        yield temp_dir, proxy_proc

    finally:
        if proxy_proc:
            terminate_process(proxy_proc, timeout=10)
        shutil.rmtree(temp_dir, ignore_errors=True)


class TestHTTP3ChainConnectValidation:
    """
    Black-box tests for HTTP/3 chain CONNECT method validation.

    These tests send raw HTTP requests to the http3_chain service's
    HTTP listener port and verify the error responses.
    """

    def test_non_connect_method_returns_405(self) -> None:
        """
        TC-CHAIN-VALIDATE-001: Non-CONNECT method returns 405.

        Send a GET request to the http3_chain service.
        Expected: 405 Method Not Allowed with text/plain body.
        """
        from .conftest import get_unique_port

        http_port = get_unique_port()
        h3_port = get_unique_port()

        with chain_service_context(http_port, h3_port) as (temp_dir, proxy_proc):
            # Send GET request (non-CONNECT)
            request = (
                b"GET / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"\r\n"
            )
            response = send_raw_request("127.0.0.1", http_port, request)

            status_code, status_text, headers, body = parse_http_response(response)

            assert status_code == 405, \
                f"Expected 405 for non-CONNECT, got {status_code}. " \
                f"Response: {response.decode(errors='ignore')}"

            assert "content-type" in headers, \
                "Expected Content-Type header in error response"
            assert "text/plain" in headers.get("content-type", ""), \
                f"Expected text/plain Content-Type, got: {headers.get('content-type')}"

    def test_post_method_returns_405(self) -> None:
        """
        TC-CHAIN-VALIDATE-002: POST method returns 405.

        Send a POST request to the http3_chain service.
        Expected: 405 Method Not Allowed.
        """
        from .conftest import get_unique_port

        http_port = get_unique_port()
        h3_port = get_unique_port()

        with chain_service_context(http_port, h3_port) as (temp_dir, proxy_proc):
            request = (
                b"POST / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: 5\r\n"
                b"\r\n"
                b"hello"
            )
            response = send_raw_request("127.0.0.1", http_port, request)

            status_code, _, _, _ = parse_http_response(response)

            assert status_code == 405, \
                f"Expected 405 for POST, got {status_code}. " \
                f"Response: {response.decode(errors='ignore')}"

    def test_connect_missing_port_returns_400(self) -> None:
        """
        TC-CHAIN-VALIDATE-003: CONNECT with missing port returns 400.

        Send a CONNECT request with no port in the target.
        Expected: 400 Bad Request.
        """
        from .conftest import get_unique_port

        http_port = get_unique_port()
        h3_port = get_unique_port()

        with chain_service_context(http_port, h3_port) as (temp_dir, proxy_proc):
            # CONNECT with no port
            request = (
                b"CONNECT example.com HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"\r\n"
            )
            response = send_raw_request("127.0.0.1", http_port, request)

            status_code, _, _, _ = parse_http_response(response)

            assert status_code == 400, \
                f"Expected 400 for missing port, got {status_code}. " \
                f"Response: {response.decode(errors='ignore')}"

    def test_connect_port_zero_returns_400(self) -> None:
        """
        TC-CHAIN-VALIDATE-004: CONNECT with port zero returns 400.

        Send a CONNECT request with port 0.
        Expected: 400 Bad Request.
        """
        from .conftest import get_unique_port

        http_port = get_unique_port()
        h3_port = get_unique_port()

        with chain_service_context(http_port, h3_port) as (temp_dir, proxy_proc):
            # CONNECT with port 0
            request = (
                b"CONNECT example.com:0 HTTP/1.1\r\n"
                b"Host: example.com:0\r\n"
                b"\r\n"
            )
            response = send_raw_request("127.0.0.1", http_port, request)

            status_code, _, _, _ = parse_http_response(response)

            assert status_code == 400, \
                f"Expected 400 for port zero, got {status_code}. " \
                f"Response: {response.decode(errors='ignore')}"

    def test_connect_no_authority_returns_400(self) -> None:
        """
        TC-CHAIN-VALIDATE-005: CONNECT with no authority returns 400.

        Send a CONNECT request with no authority (just CONNECT without target).
        Expected: 400 Bad Request.
        """
        from .conftest import get_unique_port

        http_port = get_unique_port()
        h3_port = get_unique_port()

        with chain_service_context(http_port, h3_port) as (temp_dir, proxy_proc):
            # CONNECT with no authority (empty URI path instead of host:port)
            request = (
                b"CONNECT / HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"\r\n"
            )
            response = send_raw_request("127.0.0.1", http_port, request)

            status_code, _, _, _ = parse_http_response(response)

            assert status_code == 400, \
                f"Expected 400 for no authority, got {status_code}. " \
                f"Response: {response.decode(errors='ignore')}"
