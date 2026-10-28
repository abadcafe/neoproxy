"""Verify local proxy authentication challenges survive protocol encoding."""

import asyncio
import base64
import http.client
import socket
import ssl
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_request import perform_h3_request_test
from tests.fixtures.h3_tunnel import perform_h3_connect_test_full
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process

type ListenerKind = Literal["http", "https", "http3"]
type Method = Literal["GET", "CONNECT"]
type Credentials = tuple[str, str] | None


@contextmanager
def authenticated_proxy(
    directory: Path, listener_kind: ListenerKind
) -> Generator[tuple[int, str]]:
    port = get_unique_port()
    cert, key, ca, _ = generate_test_certificates(str(directory))
    tls = ""
    if listener_kind != "http":
        tls = f"  certificates:\n  - cert_path: {cert}\n" + f"    key_path: {key}\n"
    content = f"""server_threads: 1
plugins:
  echo: {{}}
  auth: {{}}
listeners:
- name: main
  kind: {listener_kind}
  addresses: ["127.0.0.1:{port}"]
services:
- name: echo
  kind: echo.echo
  layers:
  - kind: auth.basic_auth
    users:
    - username: user
      password: password
    - username: second
      password: different
servers:
- name: echo
  listeners: [main]
  service: echo
{tls}
"""
    config = directory / "server.yaml"
    _ = config.write_text(content)
    process = start_proxy(str(config))
    try:
        assert process.wait_ready()
        yield port, ca
    finally:
        terminate_process(process, timeout=2, force=True)


def request(
    listener_kind: ListenerKind,
    port: int,
    ca: str,
    method: Method,
    credentials: Credentials,
) -> tuple[int, dict[str, str]]:
    headers: list[tuple[str, str]] = []
    if credentials is not None:
        username, password = credentials
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers.append(("proxy-authorization", f"Basic {encoded}"))
    if listener_kind == "http3":
        if method == "CONNECT":
            result = asyncio.run(
                perform_h3_connect_test_full(
                    "127.0.0.1",
                    port,
                    "example.com",
                    443,
                    ca_path=ca,
                    username=credentials[0] if credentials is not None else None,
                    password=credentials[1] if credentials is not None else None,
                    timeout=3,
                )
            )
            return result.status_code, result.response_headers
        response = asyncio.run(
            perform_h3_request_test(
                "127.0.0.1", port, method, "/", ca_path=ca, headers=headers, timeout=3
            )
        )
        return response.status_code, response.headers
    with ExitStack() as sockets:
        connection = sockets.enter_context(
            socket.create_connection(("127.0.0.1", port), timeout=3)
        )
        if listener_kind == "https":
            context = ssl.create_default_context(cafile=ca)
            connection = sockets.enter_context(
                context.wrap_socket(connection, server_hostname="localhost")
            )
        target = "example.com:443" if method == "CONNECT" else "/"
        host = "example.com:443" if method == "CONNECT" else "localhost"
        message = f"{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        message += "".join(f"{name}: {value}\r\n" for name, value in headers)
        connection.sendall((message + "\r\n").encode())
        with http.client.HTTPResponse(connection, method=method) as response:
            response.begin()
            _ = response.read()
            return response.status, {
                name.lower(): value for name, value in response.getheaders()
            }


@pytest.mark.parametrize("listener_kind", ["http", "https", "http3"])
@pytest.mark.parametrize("method", ["GET", "CONNECT"])
@pytest.mark.parametrize("credentials", [None, ("user", "wrong")])
def test_local_407_preserves_proxy_authenticate_challenge(
    tmp_path: Path,
    listener_kind: ListenerKind,
    method: Method,
    credentials: Credentials,
) -> None:
    with authenticated_proxy(tmp_path, listener_kind) as (port, ca):
        status, headers = request(listener_kind, port, ca, method, credentials)
        assert status == 407
        assert headers.get("proxy-authenticate") == 'Basic realm="proxy"'


@pytest.mark.parametrize("listener_kind", ["http", "https", "http3"])
@pytest.mark.parametrize(
    "credentials,expected",
    [
        (("user", "password"), 200),
        (("second", "different"), 200),
        (("user", "different"), 407),
        (("second", "password"), 407),
        (("unknown", "password"), 407),
    ],
)
def test_client_retries_local_challenge_and_checks_each_users_password(
    tmp_path: Path,
    listener_kind: ListenerKind,
    credentials: tuple[str, str],
    expected: int,
) -> None:
    with authenticated_proxy(tmp_path, listener_kind) as (port, ca):
        status, headers = request(listener_kind, port, ca, "GET", None)
        assert status == 407
        assert headers.get("proxy-authenticate") == 'Basic realm="proxy"'
        status, headers = request(listener_kind, port, ca, "GET", credentials)
        assert status == expected
        if expected == 407:
            assert headers.get("proxy-authenticate") == 'Basic realm="proxy"'
