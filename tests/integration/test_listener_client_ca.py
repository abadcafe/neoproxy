"""A TLS listener authenticates clients against its associated servers' CA union."""

import asyncio
import socket
import ssl
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import (
    generate_ca,
    generate_client_cert,
    generate_test_certificates,
)
from tests.fixtures.http3_client import H3Client
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process


async def _request_h3(
    port: int, ca: str, certificate: str, key: str, hostname: str
) -> None:
    client = H3Client(
        "127.0.0.1",
        port,
        ca_path=ca,
        cert_path=certificate,
        key_path=key,
        server_hostname="localhost",
    )
    try:
        async with asyncio.timeout(5):
            assert await client.connect()
            # CONNECT carries the target authority independently of TLS SNI.
            # Echo handles it as an ordinary successful request in this test.
            response = await client.send_connect_request(hostname, 443)
            assert response.status_code == 200, response
    finally:
        await client.close()


@pytest.mark.parametrize("kind", ["https", "http3"])
@pytest.mark.parametrize("issuer", [0, 1])
def test_listener_accepts_each_ca_for_both_request_servers(
    tmp_path: Path, kind: Literal["https", "http3"], issuer: int
) -> None:
    certificate, key, server_ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["localhost", "a.test", "b.test"]
    )
    authorities: list[tuple[str, str]] = []
    for name in ("a", "b"):
        directory = tmp_path / name
        directory.mkdir()
        authorities.append(generate_ca(str(directory), cn=f"Client CA {name}"))
    client_certificate, client_key = generate_client_cert(
        str(tmp_path), *authorities[issuer]
    )
    port = get_unique_port()
    config = tmp_path / "proxy.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  echo: {{}}
services:
- name: echo
  kind: echo.echo
listeners:
- name: shared
  kind: {kind}
  addresses: ["127.0.0.1:{port}"]
servers:
- name: a
  hostnames: [localhost, a.test]
  listeners: [shared]
  service: echo
  tls:
    certificates:
    - cert_path: {certificate}
      key_path: {key}
    client_ca_certs: [{authorities[0][0]}]
- name: b
  hostnames: [b.test]
  listeners: [shared]
  service: echo
  tls:
    certificates:
    - cert_path: {certificate}
      key_path: {key}
    client_ca_certs: [{authorities[1][0]}]
""")
    process = start_proxy(str(config))
    try:
        if kind == "http3":
            assert process.wait_ready(timeout=5.0)
            for hostname in ("a.test", "b.test"):
                asyncio.run(
                    _request_h3(
                        port, server_ca, client_certificate, client_key, hostname
                    )
                )
        else:
            assert process.wait_ready(timeout=5.0)
            context = ssl.create_default_context(cafile=server_ca)
            context.load_cert_chain(client_certificate, client_key)
            for hostname in ("a.test", "b.test"):
                with socket.create_connection(("127.0.0.1", port), timeout=5) as tcp:
                    with context.wrap_socket(tcp, server_hostname="localhost") as tls:
                        tls.sendall(
                            (
                                f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
                                + "Connection: close\r\n\r\n"
                            ).encode()
                        )
                        response = tls.recv(4096)
                        assert response.startswith(b"HTTP/1.1 200 "), response
    finally:
        terminate_process(process, force=True)
