"""Validate client CA configuration through the proxy process and TLS listeners."""

import asyncio
import json
import socket
import ssl
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.http3_client import H3Client
from tests.fixtures.ports import (
    get_unique_port,
    wait_for_proxy,
    wait_for_udp_port_bound,
)
from tests.fixtures.proxy_process import start_proxy, terminate_process


@dataclass(frozen=True)
class TLSMaterial:
    certificate: str
    key: str
    ca: str


@pytest.fixture
def tls_material(tmp_path: Path) -> TLSMaterial:
    certificate, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["localhost", "a.test", "b.test"]
    )
    return TLSMaterial(certificate, key, ca)


def _write_config(
    directory: Path,
    kind: Literal["https", "http3"],
    material: TLSMaterial,
    ca_paths: list[str],
    other_ca_paths: list[str],
) -> tuple[Path, int]:
    port = get_unique_port()
    config = directory / "proxy.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  echo: {{}}
services:
- name: echo
  kind: echo.echo
listeners:
- name: main
  kind: {kind}
  addresses: ["127.0.0.1:{port}"]
servers:
- name: a
  hostnames: [localhost, a.test]
  listeners: [main]
  service: echo
  tls:
    certificates:
    - cert_path: {json.dumps(material.certificate)}
      key_path: {json.dumps(material.key)}
    client_ca_certs: {json.dumps(ca_paths)}
- name: b
  hostnames: [b.test]
  listeners: [main]
  service: echo
  tls:
    certificates:
    - cert_path: {json.dumps(material.certificate)}
      key_path: {json.dumps(material.key)}
    client_ca_certs: {json.dumps(other_ca_paths)}
""")
    return config, port


async def _request_h3_without_client_certificate(port: int, ca: str) -> int:
    client = H3Client("127.0.0.1", port, ca_path=ca, server_hostname="localhost")
    try:
        async with asyncio.timeout(5):
            assert await client.connect()
            response = await client.send_connect_request("a.test", 443)
            return response.status_code
    finally:
        await client.close()


@pytest.mark.parametrize("kind", ["https", "http3"])
@pytest.mark.parametrize("other_has_ca", [False, True])
def test_empty_ca_list_allows_anonymous_requests(
    tmp_path: Path,
    tls_material: TLSMaterial,
    kind: Literal["https", "http3"],
    other_has_ca: bool,
) -> None:
    other_ca_paths = [tls_material.ca] if other_has_ca else []
    config, port = _write_config(tmp_path, kind, tls_material, [], other_ca_paths)
    process = start_proxy(str(config))
    try:
        if kind == "http3":
            assert wait_for_udp_port_bound("127.0.0.1", port, proc=process)
            assert (
                asyncio.run(
                    _request_h3_without_client_certificate(port, tls_material.ca)
                )
                == 200
            )
        else:
            assert wait_for_proxy("127.0.0.1", port, proc=process)
            context = ssl.create_default_context(cafile=tls_material.ca)
            with socket.create_connection(("127.0.0.1", port), timeout=5) as tcp:
                with context.wrap_socket(tcp, server_hostname="localhost") as tls:
                    tls.sendall(
                        b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"
                    )
                    assert tls.recv(4096).startswith(b"HTTP/1.1 200 ")
    finally:
        terminate_process(process, force=True)


@pytest.mark.parametrize("kind", ["https", "http3"])
@pytest.mark.parametrize("placement", ["same_server", "other_server"])
@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("empty", "no certificates"),
        ("whitespace", "no certificates"),
        ("text", "no certificates"),
        ("private_key", "no certificates"),
        ("bad_pem", "parse CA certificate"),
        ("bad_der", "invalid CA certificate"),
    ],
)
def test_invalid_ca_file_is_not_hidden_by_other_roots(
    tmp_path: Path,
    tls_material: TLSMaterial,
    kind: Literal["https", "http3"],
    placement: Literal["same_server", "other_server"],
    payload: str,
    expected: str,
) -> None:
    contents = {
        "empty": "",
        "whitespace": " \n\t\n",
        "text": "not a certificate\n",
        "private_key": Path(tls_material.key).read_text(),
        "bad_pem": "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        "bad_der": "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
    }
    invalid = tmp_path / "invalid-client-ca.pem"
    _ = invalid.write_text(contents[payload])
    ca_paths = [tls_material.ca]
    other_ca_paths: list[str] = []
    if placement == "same_server":
        ca_paths.append(str(invalid))
    else:
        other_ca_paths.append(str(invalid))
    config, _ = _write_config(tmp_path, kind, tls_material, ca_paths, other_ca_paths)
    process = start_proxy(str(config))
    try:
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            terminate_process(process, force=True)
            pytest.fail("Proxy accepted an invalid client CA file")
        # TLS configuration errors now fail before worker/log startup.
        assert process.returncode == 1, (stdout, stderr)
        diagnostic = (stdout + stderr).decode()
        assert str(invalid) in diagnostic, diagnostic
        assert "client_ca_certs[" in diagnostic, diagnostic
        assert expected in diagnostic, diagnostic
        assert not (tmp_path / "logs").exists()
    finally:
        terminate_process(process, force=True)
