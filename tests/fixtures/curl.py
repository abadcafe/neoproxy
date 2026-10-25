"""module: curl; responsibility: curl fixtures.
Public operations: curl_request, curl_request_with_headers,
get_curl_env_without_no_proxy.
Tests: sibling module tests and public fixture consumers.
"""

import os
import subprocess


def curl_request(
    url: str,
    proxy_port: int,
    headers: dict[str, str] | None = None,
    timeout: int = 5,
) -> int:
    """Make an HTTP request through the proxy using curl.

    Args:
        url: Target URL to request.
        proxy_port: Port the proxy is listening on.
        headers: Optional HTTP headers to include.
        timeout: Request timeout in seconds.

    Returns:
        HTTP status code (int). Returns 0 on parse failure.
    """
    cmd = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-x",
        f"http://127.0.0.1:{proxy_port}",
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
    ]

    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    cmd.append(url)

    env = get_curl_env_without_no_proxy()

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout + 2,
        env=env,
    )
    status_code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
    return status_code


def curl_request_with_headers(
    url: str,
    proxy_port: int,
    headers: dict[str, str] | None = None,
    timeout: int = 5,
) -> tuple[int, dict[str, str], str]:
    """Make an HTTP request through the proxy using curl, capturing response headers.

    Args:
        url: Target URL to request.
        proxy_port: Port the proxy is listening on.
        headers: Optional HTTP headers to include.
        timeout: Request timeout in seconds.

    Returns:
        Tuple of (status_code, response_headers_dict, body).
    """
    cmd = [
        "curl",
        "-s",
        "-D",
        "-",
        "-x",
        f"http://127.0.0.1:{proxy_port}",
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
    ]

    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    cmd.append(url)

    env = get_curl_env_without_no_proxy()

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout + 2,
        env=env,
    )
    output = result.stdout

    # Parse status line and headers
    lines = output.split("\n")
    status_code = 0
    response_headers: dict[str, str] = {}
    body_start = len(lines)

    for i, line in enumerate(lines):
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    pass
        elif ":" in line and line.strip():
            key, _, value = line.partition(":")
            response_headers[key.strip().lower()] = value.strip()
        elif line.strip() == "":
            body_start = i + 1
            break

    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    return status_code, response_headers, body


def get_curl_env_without_no_proxy() -> dict[str, str]:
    """
    Get a copy of the environment with no_proxy cleared for curl.

    This is needed to force curl to use the proxy for localhost addresses,
    which are normally excluded by no_proxy environment variables.

    Returns:
        dict: Environment dict with no_proxy and NO_PROXY cleared
    """
    env = os.environ.copy()
    env["no_proxy"] = ""
    env["NO_PROXY"] = ""
    return env
