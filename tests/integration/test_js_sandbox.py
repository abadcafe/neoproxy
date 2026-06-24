"""
Integration tests for js_sandbox plugin.

Tests the full request lifecycle: HTTP request → neoproxy → sandbox pool →
V8 isolate → JS handler → response. Uses the proxy_with_config fixture to
start a real neoproxy process and sends requests via curl.
"""

import json
import os
import subprocess
import threading

from .conftest import get_unique_port
from .types import (
    ConfigDict,
    ProxyWithConfig,
)
from .utils.helpers import (
    create_target_server,
    http_echo_handler,
    wait_for_proxy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SIMPLE_HANDLER = 'export default { async fetch(req) {  return new Response("hello from sandbox", { status: 200 });}};'

ECHO_METHOD_HANDLER = "export default { async fetch(req) {  return new Response(req.method, { status: 200 });}};"

ECHO_BODY_HANDLER = (
    "export default { async fetch(req) {"
    "  const body = await req.text();"
    "  return new Response(body, { status: 200 });"
    "}};"
)

ECHO_HEADERS_HANDLER = (
    "export default { async fetch(req) {"
    '  const hdr = req.headers.get("x-custom");'
    '  return new Response(hdr || "none", { status: 200 });'
    "}};"
)

ECHO_URL_HANDLER = (
    "export default { async fetch(req) {"
    "  const u = new URL(req.url);"
    "  return new Response(u.pathname + u.search, { status: 200 });"
    "}};"
)

THROW_HANDLER = 'export default { async fetch(req) {  throw new Error("intentional crash");}};'

NO_FETCH_HANDLER = "export default { };"

NO_DEFAULT_EXPORT_HANDLER = "export const x = 1;"

SYNTAX_ERROR_HANDLER = "export default { async fetch(req) { return @@@; } };"

BAD_RETURN_HANDLER = "export default { async fetch(req) { return 'not a response'; } };"

UNICODE_HANDLER = (
    "export default { async fetch(req) {"
    '  return new Response("\\u4f60\\u597d\\u4e16\\u754c", {'
    "    status: 200,"
    '    headers: { "content-type": "text/plain; charset=utf-8" },'
    "  });"
    "}};"
)

JSON_HANDLER = (
    "export default { async fetch(req) {"
    "  const data = await req.json();"
    "  return new Response(JSON.stringify({ echo: data.name }), {"
    "    status: 200,"
    '    headers: { "content-type": "application/json" },'
    "  });"
    "}};"
)

CUSTOM_HEADERS_HANDLER = (
    "export default { async fetch(req) {"
    '  return new Response("ok", {'
    "    status: 200,"
    '    headers: { "x-response": "from-sandbox", "content-type": "text/plain" },'
    "  });"
    "}};"
)

EMPTY_BODY_HANDLER = 'export default { async fetch(req) {  return new Response("", { status: 200 });}};'

NO_CONTENT_HANDLER = "export default { async fetch(req) {  return new Response(null, { status: 204 });}};"

LARGE_BODY_HANDLER = (
    "export default { async fetch(req) {"
    '  const str = "x".repeat(100000);'
    "  return new Response(str, { status: 200 });"
    "}};"
)

BINARY_BODY_HANDLER = (
    "export default { async fetch(req) {"
    "  const arr = new Uint8Array([0, 1, 2, 255, 254, 253]);"
    "  return new Response(arr, { status: 200 });"
    "}};"
)


def _write_js(source_dir: str, name: str, code: str) -> None:
    """Write a JS handler file to source_dir/{name}.js."""
    path = os.path.join(source_dir, f"{name}.js")
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)


def _make_sandbox_config(source_dir: str, worker_threads: int = 2) -> ConfigDict:
    """Build a neoproxy config dict with js_sandbox plugin."""
    return {
        "server_threads": 1,
        "plugins": {
            "js_sandbox": {
                "source_dir": source_dir,
                "worker_threads": worker_threads,
                "default_cpu_limit_ms": 5000,
                "default_mem_limit_mb": 128,
            },
        },
        "listeners": [
            {
                "name": "http_main",
                "kind": "http",
                "addresses": ["127.0.0.1:AUTO_PORT"],
            },
        ],
        "services": [
            {
                "name": "sandbox_svc",
                "kind": "js_sandbox.sandbox",
            },
        ],
        "servers": [
            {
                "name": "sandbox_server",
                "hostnames": [],
                "listeners": ["http_main"],
                "service": "sandbox_svc",
            },
        ],
    }


def _curl_get(
    port: int,
    path: str = "/",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> tuple[int, dict[str, str], str]:
    """Send a GET request via curl to the sandbox proxy.

    Returns (status_code, response_headers, body).
    """
    url = f"http://127.0.0.1:{port}{path}"
    cmd = ["curl", "-s", "-D", "-", "--max-time", str(timeout), url]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    return _parse_curl_output(result.stdout)


def _curl_request(
    method: str,
    port: int,
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 10,
) -> tuple[int, dict[str, str], str]:
    """Send an HTTP request via curl to the sandbox proxy.

    Returns (status_code, response_headers, body).
    """
    url = f"http://127.0.0.1:{port}{path}"
    cmd = [
        "curl",
        "-s",
        "-D",
        "-",
        "-X",
        method,
        "--max-time",
        str(timeout),
        url,
    ]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if body is not None:
        cmd.extend(["-d", body])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    return _parse_curl_output(result.stdout)


def _curl_request_binary(
    method: str,
    port: int,
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> tuple[int, dict[str, str], bytes]:
    """Send an HTTP request via curl, returning raw bytes for body."""
    url = f"http://127.0.0.1:{port}{path}"
    cmd = [
        "curl",
        "-s",
        "-D",
        "-",
        "-X",
        method,
        "--max-time",
        str(timeout),
        url,
    ]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if body is not None:
        cmd.extend(["--data-binary", "@-"])
        result = subprocess.run(cmd, input=body, capture_output=True, timeout=timeout + 5)
    else:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
    return _parse_curl_output_bytes(result.stdout)


def _parse_curl_output(raw: str) -> tuple[int, dict[str, str], str]:
    """Parse curl -D - output into (status, headers, body)."""
    # Normalize line endings
    raw = raw.replace("\r\n", "\n")
    # Split headers from body at the first blank line
    parts = raw.split("\n\n", 1)
    header_section = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = header_section.split("\n")

    # Find the final HTTP status line (skip 100 Continue etc.)
    status = 0
    headers: dict[str, str] = {}
    header_started = False
    for line in lines:
        if line.startswith("HTTP/"):
            status = int(line.split(" ", 2)[1])
            headers = {}
            header_started = True
        elif header_started and ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return status, headers, body


def _parse_curl_output_bytes(
    raw: bytes,
) -> tuple[int, dict[str, str], bytes]:
    """Parse curl -D - output with raw bytes body."""
    # Normalize line endings
    raw = raw.replace(b"\r\n", b"\n")
    parts = raw.split(b"\n\n", 1)
    header_section = parts[0].decode("utf-8", errors="replace")
    body = parts[1] if len(parts) > 1 else b""

    lines = header_section.split("\n")

    status = 0
    headers: dict[str, str] = {}
    header_started = False
    for line in lines:
        if line.startswith("HTTP/"):
            status = int(line.split(" ", 2)[1])
            headers = {}
            header_started = True
        elif header_started and ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return status, headers, body


# ---------------------------------------------------------------------------
# Test Classes
# ---------------------------------------------------------------------------


class TestSandboxMissingId:
    """Tests for requests without sandbox-id header."""

    def test_missing_sandbox_id_returns_400(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, body = _curl_get(proxy.port)
            assert status == 400
            assert "missing sandbox-id" in body.lower()


class TestSandboxNotFound:
    """Tests for nonexistent sandbox-id."""

    def test_nonexistent_sandbox_returns_404(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, body = _curl_get(proxy.port, headers={"sandbox-id": "nonexistent"})
            assert status == 404
            assert "sandbox not found" in body.lower()

    def test_empty_sandbox_id_returns_error(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, _body = _curl_get(proxy.port, headers={"sandbox-id": ""})
            # curl strips empty header values; service sees no sandbox-id → 400
            assert status in (400, 404)


class TestSandboxSimpleResponse:
    """Tests for basic sandbox request/response."""

    def test_simple_handler_returns_200(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, body = _curl_get(proxy.port, headers={"sandbox-id": "hello"})
            assert status == 200
            assert body == "hello from sandbox"

    def test_handler_returns_custom_status(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(
            source_dir,
            "created",
            'export default { async fetch(req) {  return new Response("created", { status: 201 });}};',
        )

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, body = _curl_get(proxy.port, headers={"sandbox-id": "created"})
            assert status == 201
            assert body == "created"

    def test_handler_returns_500(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(
            source_dir,
            "server_err",
            'export default { async fetch(req) {  return new Response("boom", { status: 500 });}};',
        )

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, body = _curl_get(proxy.port, headers={"sandbox-id": "server_err"})
            assert status == 500
            assert body == "boom"


class TestSandboxHttpMethods:
    """Tests for different HTTP methods."""

    def test_get_request(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_method", ECHO_METHOD_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_request("GET", proxy.port, headers={"sandbox-id": "echo_method"})
            assert status == 200
            assert body == "GET"

    def test_post_request(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_method", ECHO_METHOD_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_request(
                "POST",
                proxy.port,
                headers={"sandbox-id": "echo_method"},
            )
            assert status == 200
            assert body == "POST"

    def test_put_request(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_method", ECHO_METHOD_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_request("PUT", proxy.port, headers={"sandbox-id": "echo_method"})
            assert status == 200
            assert body == "PUT"

    def test_delete_request(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_method", ECHO_METHOD_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_request(
                "DELETE",
                proxy.port,
                headers={"sandbox-id": "echo_method"},
            )
            assert status == 200
            assert body == "DELETE"

    def test_patch_request(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_method", ECHO_METHOD_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_request(
                "PATCH",
                proxy.port,
                headers={"sandbox-id": "echo_method"},
            )
            assert status == 200
            assert body == "PATCH"


class TestSandboxRequestBody:
    """Tests for request body passthrough."""

    def test_post_body_echo(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_body", ECHO_BODY_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_request(
                "POST",
                proxy.port,
                headers={
                    "sandbox-id": "echo_body",
                    "content-type": "text/plain",
                },
                body="hello-body-data",
            )
            assert status == 200
            assert body == "hello-body-data"

    def test_json_request_parsing(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "json_parse", JSON_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            payload = json.dumps({"name": "test-user"})
            status, _, body = _curl_request(
                "POST",
                proxy.port,
                headers={
                    "sandbox-id": "json_parse",
                    "content-type": "application/json",
                },
                body=payload,
            )
            assert status == 200
            result = json.loads(body)
            assert result == {"echo": "test-user"}


class TestSandboxRequestHeaders:
    """Tests for request header passthrough."""

    def test_custom_header_echo(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_headers", ECHO_HEADERS_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(
                proxy.port,
                headers={
                    "sandbox-id": "echo_headers",
                    "x-custom": "my-header-value",
                },
            )
            assert status == 200
            assert body == "my-header-value"


class TestSandboxRequestUrl:
    """Tests for request URL/path passthrough."""

    def test_url_path_echo(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "echo_url", ECHO_URL_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(
                proxy.port,
                path="/some/path?q=val",
                headers={"sandbox-id": "echo_url"},
            )
            assert status == 200
            assert body == "/some/path?q=val"


class TestSandboxResponseHeaders:
    """Tests for response headers from JS handler."""

    def test_custom_response_headers(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "custom_hdr", CUSTOM_HEADERS_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, headers, _body = _curl_get(proxy.port, headers={"sandbox-id": "custom_hdr"})
            assert status == 200
            assert headers.get("x-response") == "from-sandbox"
            assert "text/plain" in headers.get("content-type", "")

    def test_json_response_content_type(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(
            source_dir,
            "json_resp",
            "export default { async fetch(req) {"
            '  return new Response(\'{"hello":"world"}\', {'
            "    status: 200,"
            '    headers: { "content-type": "application/json" },'
            "  });"
            "}};",
        )

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, headers, body = _curl_get(proxy.port, headers={"sandbox-id": "json_resp"})
            assert status == 200
            assert "application/json" in headers.get("content-type", "")
            assert json.loads(body) == {"hello": "world"}


class TestSandboxJsErrors:
    """Tests for JS handler error handling."""

    def test_handler_throws_returns_502(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "thrower", THROW_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, _body = _curl_get(proxy.port, headers={"sandbox-id": "thrower"})
            assert status == 502

    def test_handler_without_fetch_returns_502(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "no_fetch", NO_FETCH_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, _ = _curl_get(proxy.port, headers={"sandbox-id": "no_fetch"})
            assert status == 502

    def test_handler_without_default_export_returns_502(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "no_export", NO_DEFAULT_EXPORT_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, _ = _curl_get(proxy.port, headers={"sandbox-id": "no_export"})
            assert status == 502

    def test_syntax_error_returns_502(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "bad_syntax", SYNTAX_ERROR_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, _ = _curl_get(proxy.port, headers={"sandbox-id": "bad_syntax"})
            assert status == 502

    def test_handler_returns_non_response_returns_502(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "bad_return", BAD_RETURN_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, _ = _curl_get(proxy.port, headers={"sandbox-id": "bad_return"})
            assert status == 502


class TestSandboxResponseBody:
    """Tests for response body edge cases."""

    def test_empty_body(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "empty_body", EMPTY_BODY_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(proxy.port, headers={"sandbox-id": "empty_body"})
            assert status == 200
            assert body == ""

    def test_no_content_204(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "no_content", NO_CONTENT_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, _body = _curl_get(proxy.port, headers={"sandbox-id": "no_content"})
            assert status == 204

    def test_unicode_body(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "unicode", UNICODE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, body = _curl_get(proxy.port, headers={"sandbox-id": "unicode"})
            assert status == 200
            assert body == "你好世界"

    def test_large_body(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "large_body", LARGE_BODY_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(proxy.port, headers={"sandbox-id": "large_body"})
            assert status == 200
            assert len(body) == 100000
            assert body == "x" * 100000

    def test_binary_body(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "binary_body", BINARY_BODY_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _headers, body = _curl_request_binary(
                "GET",
                proxy.port,
                headers={"sandbox-id": "binary_body"},
            )
            assert status == 200
            assert body == bytes([0, 1, 2, 255, 254, 253])


class TestSandboxCustomLimits:
    """Tests for sandbox-mem and sandbox-cpu headers."""

    def test_custom_mem_header_accepted(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(
                proxy.port,
                headers={"sandbox-id": "hello", "sandbox-mem": "256"},
            )
            assert status == 200
            assert body == "hello from sandbox"

    def test_custom_cpu_header_accepted(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(
                proxy.port,
                headers={"sandbox-id": "hello", "sandbox-cpu": "10000"},
            )
            assert status == 200
            assert body == "hello from sandbox"

    def test_invalid_mem_uses_default(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(
                proxy.port,
                headers={
                    "sandbox-id": "hello",
                    "sandbox-mem": "not-a-number",
                },
            )
            assert status == 200
            assert body == "hello from sandbox"

    def test_invalid_cpu_uses_default(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status, _, body = _curl_get(
                proxy.port,
                headers={
                    "sandbox-id": "hello",
                    "sandbox-cpu": "garbage",
                },
            )
            assert status == 200
            assert body == "hello from sandbox"


class TestSandboxMultipleHandlers:
    """Tests for different sandbox-id values routing to different handlers."""

    def test_different_handlers(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(
            source_dir,
            "handler_a",
            'export default { async fetch(req) {  return new Response("handler-a", { status: 200 });}};',
        )
        _write_js(
            source_dir,
            "handler_b",
            'export default { async fetch(req) {  return new Response("handler-b", { status: 200 });}};',
        )

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            status_a, _, body_a = _curl_get(proxy.port, headers={"sandbox-id": "handler_a"})
            assert status_a == 200
            assert body_a == "handler-a"

            status_b, _, body_b = _curl_get(proxy.port, headers={"sandbox-id": "handler_b"})
            assert status_b == 200
            assert body_b == "handler-b"


class TestSandboxSequentialRequests:
    """Tests for multiple sequential requests to the same handler."""

    def test_sequential_requests(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
            for _ in range(10):
                status, _, body = _curl_get(proxy.port, headers={"sandbox-id": "hello"})
                assert status == 200
                assert body == "hello from sandbox"


class TestSandboxConcurrentRequests:
    """Tests for concurrent requests to the sandbox."""

    def test_concurrent_requests(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)
        _write_js(source_dir, "hello", SIMPLE_HANDLER)

        with proxy_with_config(_make_sandbox_config(source_dir, worker_threads=4)) as proxy:
            results: list[tuple[int, str] | None] = [None] * 10
            errors: list[BaseException] = []

            def do_request(idx: int) -> None:
                try:
                    status, _, body = _curl_get(proxy.port, headers={"sandbox-id": "hello"})
                    results[idx] = (status, body)
                except (OSError, subprocess.SubprocessError) as e:
                    errors.append(e)

            threads = [threading.Thread(target=do_request, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert not errors, f"errors in concurrent requests: {errors}"
            for result in results:
                assert result is not None
                status, body = result
                assert status == 200
                assert body == "hello from sandbox"


class TestSandboxOutboundFetch:
    """Tests for outbound fetch from inside the sandbox."""

    def test_handler_makes_outbound_fetch(self, proxy_with_config: ProxyWithConfig, temp_dir: str):
        source_dir = os.path.join(temp_dir, "scripts")
        os.makedirs(source_dir)

        # Start a local HTTP target server
        target_port = get_unique_port()
        _thread, target_sock = create_target_server("127.0.0.1", target_port, http_echo_handler)
        assert wait_for_proxy("127.0.0.1", target_port, timeout=2.0), "target server failed to start"

        try:
            upstream_url = f"http://127.0.0.1:{target_port}"
            _write_js(
                source_dir,
                "fetch_upstream",
                f"export default {{ async fetch(req) {{ "
                f"  try {{ "
                f'    const resp = await fetch("{upstream_url}"); '
                f"    const body = await resp.text(); "
                f"    return new Response(body, {{ status: resp.status }}); "
                f"  }} catch(e) {{ "
                f"    return new Response(String(e), {{ status: 502 }}); "
                f"  }} "
                f"}}}};",
            )

            with proxy_with_config(_make_sandbox_config(source_dir)) as proxy:
                status, _, body = _curl_get(proxy.port, headers={"sandbox-id": "fetch_upstream"})
                assert status == 200
                assert "OK" in body
        finally:
            target_sock.close()
