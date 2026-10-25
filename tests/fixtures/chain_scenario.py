"""chain scenario fixture interface.
Tests: process and protocol consumers.
"""

import shutil
import socket
import subprocess
import threading

from tests.fixtures.certificates import generate_client_cert, generate_test_certificates
from tests.fixtures.chain_configuration import (
    create_entry_http_password_config,
    create_entry_http_tls_cert_config,
    create_entry_socks5_password_config,
    create_entry_socks5_tls_cert_config,
    create_upstream_password_config,
    create_upstream_tls_cert_config,
)
from tests.fixtures.configuration import StringMap
from tests.fixtures.http_echo import http_echo_handler
from tests.fixtures.ports import (
    wait_for_proxy,
    wait_for_udp_port_bound,
)
from tests.fixtures.proxy_process import BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server


def create_echo_target_server(
    host: str, port: int
) -> tuple[threading.Thread, socket.socket]:
    """
    Create an HTTP echo target server for testing.

    This server properly parses HTTP requests and echoes POST body back
    in a valid HTTP 200 response, compatible with curl's HTTP protocol
    expectations (CR-011).

    Args:
        host: Listen address
        port: Listen port

    Returns:
        tuple[threading.Thread, socket.socket]: Server thread and socket
    """
    return create_target_server(host, port, http_echo_handler)


def run_proxy_chain_test(
    entry_type: str,  # "http" or "socks5"
    upstream_auth: str,  # "password" or "tls_cert"
    target_type: str,  # "baidu" or "mock"
    http_port: int,
    h3_port: int,
    target_port: int | None,
    temp_dir1: str,
    temp_dir2: str,
    shared_test_certs: StringMap | None = None,
    shared_client_cert: StringMap | None = None,
) -> None:
    """
    Run a proxy chain test with the specified configuration.

    This function consolidates the common test logic to reduce code duplication.

    Args:
        entry_type: Entry proxy type ("http" or "socks5")
        upstream_auth: Upstream auth type ("password" or "tls_cert")
        target_type: Target type ("baidu" or "mock")
        http_port: Entry HTTP/SOCKS5 port
        h3_port: Upstream HTTP/3 port
        target_port: Target server port (for mock tests)
        temp_dir1: Temp dir for upstream
        temp_dir2: Temp dir for entry
        shared_test_certs: Optional session-scoped cert dict for cert reuse
        shared_client_cert: Optional session-scoped client cert dict for cert reuse
    """
    upstream_proc: BytesProcess | None = None
    entry_proc: BytesProcess | None = None
    target_socket: socket.socket | None = None

    try:
        if shared_test_certs:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            ca_key_path = shared_test_certs["ca_key_path"]
        else:
            cert_path, key_path, ca_path, ca_key_path = generate_test_certificates(
                temp_dir1
            )

        # Get client certificate for TLS cert auth
        client_cert_path = None
        client_key_path = None
        if upstream_auth == "tls_cert":
            if shared_client_cert:
                client_cert_path = shared_client_cert["client_cert_path"]
                client_key_path = shared_client_cert["client_key_path"]
            else:
                client_cert_path, client_key_path = generate_client_cert(
                    temp_dir1, ca_path, ca_key_path
                )

        # Create upstream config
        if upstream_auth == "password":
            upstream_config = create_upstream_password_config(
                h3_port, cert_path, key_path, temp_dir1
            )
        else:
            upstream_config = create_upstream_tls_cert_config(
                h3_port, cert_path, key_path, ca_path, temp_dir1
            )

        upstream_proc = start_proxy(upstream_config)
        assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), (
            "Upstream HTTP/3 listener failed to start"
        )

        # Create entry config
        if entry_type == "http":
            if upstream_auth == "password":
                entry_config = create_entry_http_password_config(
                    http_port, h3_port, ca_path, temp_dir2
                )
            else:
                assert client_cert_path is not None and client_key_path is not None
                entry_config = create_entry_http_tls_cert_config(
                    http_port,
                    h3_port,
                    ca_path,
                    client_cert_path,
                    client_key_path,
                    temp_dir2,
                )
        else:  # socks5
            if upstream_auth == "password":
                entry_config = create_entry_socks5_password_config(
                    http_port, h3_port, ca_path, temp_dir2
                )
            else:
                assert client_cert_path is not None and client_key_path is not None
                entry_config = create_entry_socks5_tls_cert_config(
                    http_port,
                    h3_port,
                    ca_path,
                    client_cert_path,
                    client_key_path,
                    temp_dir2,
                )

        entry_proc = start_proxy(entry_config)
        assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), (
            "Entry listener failed to start"
        )

        # Create target server for mock tests
        if target_type == "mock" and target_port:
            _, target_socket = create_echo_target_server("127.0.0.1", target_port)

        # Run curl
        if entry_type == "http":
            curl_proxy = f"http://user1:pass1@127.0.0.1:{http_port}"
            curl_cmd = ["curl", "-p", "-x", curl_proxy]
        else:  # socks5
            curl_cmd = [
                "curl",
                "--socks5-basic",
                "--socks5-hostname",
                f"127.0.0.1:{http_port}",
                "--proxy-user",
                "user1:pass1",
            ]

        if target_type == "baidu":
            curl_cmd.extend(
                [
                    "https://www.baidu.com",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--connect-timeout",
                    "30",
                ]
            )
            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            assert result.stdout == "200", (
                f"Expected 200, got {result.stdout}. stderr: {result.stderr}"
            )
        else:  # mock
            curl_cmd.extend(
                [
                    f"http://127.0.0.1:{target_port}",
                    "-d",
                    "test_data_chain",
                    "--connect-timeout",
                    "5",
                ]
            )
            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            assert "test_data_chain" in result.stdout, (
                f"Expected echo, got stdout: {result.stdout}, stderr: {result.stderr}"
            )

    finally:
        if entry_proc:
            entry_proc.kill()
            _ = entry_proc.wait(timeout=5)
        if upstream_proc:
            upstream_proc.kill()
            _ = upstream_proc.wait(timeout=5)
        if target_socket:
            target_socket.close()
        shutil.rmtree(temp_dir1, ignore_errors=True)
        shutil.rmtree(temp_dir2, ignore_errors=True)


def is_proxy_auth_response(result: subprocess.CompletedProcess[str]) -> bool:
    """Check if a curl result indicates a 407 Proxy Authentication Required response.

    For CONNECT tunnels (HTTPS through HTTP proxy), curl reports 'response 407'
    in stderr while %{http_code} shows '000'. The exit code varies by curl
    version and should NOT be relied upon for specific values.

    For plain HTTP proxy requests, curl returns HTTP code 407 normally.

    Args:
        result: CompletedProcess from curl subprocess run

    Returns:
        True if the response indicates 407 Proxy Authentication Required
    """
    # Case 1: Plain HTTP proxy request - HTTP status code 407 in stdout
    if result.stdout.strip() == "407":
        return True
    # Case 2: CONNECT tunnel - check stderr for "response 407" pattern.
    # Do NOT check specific exit codes (7, 56, etc.) - they vary by curl version.
    # The "response 407" pattern is specific enough to avoid false positives.
    if "response 407" in result.stderr.lower():
        return True
    return False
