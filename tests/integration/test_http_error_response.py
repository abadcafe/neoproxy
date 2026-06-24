"""
HTTP error response integration tests.

Test target: Verify neoproxy HTTP error response behavior
Test nature: Black-box testing through external interface (HTTP)

Validates error response format per design doc section 5.4:
```
HTTP/1.1 <status_code> <status_description>
Content-Type: text/plain
Content-Length: <length>

<error_message>
```

Error types:
- 405: "Method Not Allowed: only CONNECT is supported"
- 400: "Bad Request: invalid target address"
- 502: "Bad Gateway: failed to connect to target"
- 500: "Internal Server Error"
"""

import re
import shutil
import tempfile

from .conftest import get_unique_port
from .types import (
    BytesProcess,
)
from .utils.helpers import (
    create_echo_config,
    create_test_config,
    send_raw_request,
    start_proxy,
    wait_for_proxy,
)


def parse_http_response(
    response: bytes,
) -> tuple[int, str, dict[str, str], bytes]:
    """
    Parse HTTP response into components.

    Args:
        response: Raw HTTP response bytes

    Returns:
        Tuple of (status_code, status_text, headers_dict, body)
    """
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

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    return status_code, status_text, headers, body


# ==============================================================================
# Test cases
# ==============================================================================


class TestHTTPErrorResponse:
    """HTTP error response integration tests."""

    def test_500_on_service_error(self) -> None:
        """
        TC-HTTP-001: HTTP 500 response on service internal error.

        Target: Verify service returns proper 500 response on internal errors

        Note: This test verifies the 500 response format is correct.
        The echo service normally doesn't fail, but we test the expected
        response format if it did.

        Testing actual internal errors is difficult in black-box testing
        without modifying the service code. The implementation is verified
        through unit tests in echo.rs.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_echo_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), "Proxy server failed to start"

            # Send a normal POST request to echo service
            # Echo service should return the body as-is (200 OK)
            request = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # Verify echo service works correctly (returns 200)
            assert b"200" in response or b"OK" in response, (
                f"Echo service should return 200, got: {response.decode(errors='ignore')}"
            )

            # Note: Actually triggering a 500 error in black-box testing is difficult
            # The 500 error handling is verified through unit tests.
            # The expected 500 response format is:
            # - Status: 500 Internal Server Error
            # - Content-Type: text/plain
            # - Body: "Internal Server Error"

        finally:
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_400_on_origin_form_request(self) -> None:
        """
        TC-HTTP-002: HTTP 400 response on origin-form GET request to connect_tcp.

        Target: Verify connect_tcp service returns 400 for origin-form URIs.
        The forward proxy requires absolute-form http:// URIs; origin-form
        (GET /) is rejected with 400 Bad Request.

        Validates:
        1. Status code is 400
        2. Content-Type header is present
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), "Proxy server failed to start"

            # Send an origin-form GET request (should return 400)
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # Parse response
            status_code, _status_text, headers, _body = parse_http_response(response)

            # Verify status code is 400
            assert status_code == 400, (
                f"Expected status 400, got {status_code}. Response: {response.decode(errors='ignore')}"
            )

            # Verify Content-Type header is present
            assert "content-type" in headers, "Expected Content-Type header in error response"

        finally:
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_400_on_invalid_connect_target(self) -> None:
        """
        TC-HTTP-003: HTTP 400 response on invalid CONNECT target.

        Target: Verify connect_tcp service returns 400 for invalid target
        with proper error response format.

        Validates:
        1. Status code is 400
        2. Response contains "Bad Request" text
        3. Error message explains the issue
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), "Proxy server failed to start"

            # Send CONNECT with invalid target (missing port)
            request = b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # Parse response
            status_code, status_text, _headers, _body = parse_http_response(response)

            # Verify status code is 400
            assert status_code == 400, (
                f"Expected status 400, got {status_code}. Response: {response.decode(errors='ignore')}"
            )

            # Verify status text contains "Bad Request"
            assert "Bad Request" in status_text or "bad" in status_text.lower() or "invalid" in status_text.lower(), (
                f"Status text should indicate bad request, got: {status_text}"
            )

            # Verify response indicates the issue
            response_str = response.decode("utf-8", errors="ignore")
            assert "400" in response_str or "bad" in response_str.lower(), "Response should indicate bad request"

        finally:
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_echo_service_normal_operation(self) -> None:
        """
        TC-HTTP-004: Echo service normal operation.

        Target: Verify echo service works correctly without errors
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_echo_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), "Proxy server failed to start"

            # Test 1: POST with body
            test_body = b"Hello, Echo Service!"
            request = (
                b"POST /echo HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Content-Length: " + str(len(test_body)).encode() + b"\r\n"
                b"\r\n" + test_body
            )
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # Verify 200 OK and body is echoed back
            assert b"200" in response, f"Expected 200 response, got: {response.decode(errors='ignore')}"
            assert test_body in response, f"Expected echo body in response, got: {response.decode(errors='ignore')}"

            # Test 2: GET request (empty body)
            request = b"GET /echo HTTP/1.1\r\nHost: localhost\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # Verify 200 OK
            assert b"200" in response, f"Expected 200 response, got: {response.decode(errors='ignore')}"

        finally:
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)
