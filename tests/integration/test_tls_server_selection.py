"""Real TLS/QUIC contracts for listener-scoped servers and certificate candidates."""

import asyncio
import datetime
import socket
import ssl
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import ConfigDict, dict_to_yaml
from tests.fixtures.h3_lifecycle import LifecycleClient
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer


@dataclass(frozen=True)
class Credential:
    cert: Path
    key: Path
    der: bytes


def _credential(
    directory: Path, name: str, names: list[str], algorithm: Literal["rsa", "ec"]
) -> Credential:
    key = (
        rsa.generate_private_key(65537, 2048)
        if algorithm == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in names]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
    _ = cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _ = key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return Credential(
        cert_path, key_path, cert.public_bytes(serialization.Encoding.DER)
    )


def _server(
    name: str, hostnames: list[str], credentials: list[Credential]
) -> ConfigDict:
    return {
        "name": name,
        "hostnames": [value for value in hostnames],
        "listeners": ["main"],
        "service": "direct",
        "certificates": [
            {"cert_path": str(value.cert), "key_path": str(value.key)}
            for value in credentials
        ],
    }


@contextmanager
def _proxy(
    directory: Path,
    servers: list[ConfigDict],
    kind: Literal["https", "http3"] = "https",
) -> Generator[int]:
    port = get_unique_port()
    config: ConfigDict = {
        "server_threads": 2,
        "plugins": {"upstream": {"upstreams": [{"name": "direct"}]}},
        "listeners": [
            {"name": "main", "kind": kind, "addresses": [f"127.0.0.1:{port}"]}
        ],
        "services": [
            {
                "name": "direct",
                "kind": "upstream.upstream",
                "upstream": "direct",
            }
        ],
        "servers": [value for value in servers],
    }
    path = directory / "proxy.yaml"
    _ = path.write_text(dict_to_yaml(config))
    process = start_proxy(str(path))
    try:
        assert process.wait_ready()
        yield port
    finally:
        terminate_process(process, timeout=7)
    assert process.returncode == 0


def _context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


@pytest.mark.parametrize(
    ("version", "cipher", "order", "expected"),
    [
        (ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256", "ec-first", "rsa"),
        (ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-AES128-GCM-SHA256", "rsa-first", "ec"),
        (ssl.TLSVersion.TLSv1_3, None, "ec-first", "ec"),
        (ssl.TLSVersion.TLSv1_3, None, "rsa-first", "rsa"),
        (ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-GCM-SHA256", "ec-only", "reject"),
    ],
)
def test_tls_selects_first_compatible_certificate_without_cross_server_fallback(
    tmp_path: Path,
    version: ssl.TLSVersion,
    cipher: str | None,
    order: Literal["ec-first", "rsa-first", "ec-only"],
    expected: Literal["ec", "rsa", "reject"],
) -> None:
    ec_cert = _credential(tmp_path, "ec", ["proxy.test"], "ec")
    rsa_cert = _credential(tmp_path, "rsa", ["proxy.test"], "rsa")
    candidates = [rsa_cert, ec_cert] if order == "rsa-first" else [ec_cert, rsa_cert]
    if order == "ec-only":
        candidates = [ec_cert]
    with _proxy(
        tmp_path,
        [
            _server("named", ["proxy.test"], candidates),
            _server("default", [], [rsa_cert]),
        ],
    ) as port:
        context = _context()
        context.minimum_version = version
        context.maximum_version = version
        if cipher is not None:
            context.set_ciphers(cipher)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
            try:
                tls = context.wrap_socket(tcp, server_hostname="proxy.test")
            except ssl.SSLError:
                assert expected == "reject"
            else:
                with tls:
                    assert expected != "reject"
                    chosen = ec_cert if expected == "ec" else rsa_cert
                    assert tls.getpeercert(binary_form=True) == chosen.der


def test_tls_extra_san_does_not_create_a_server_route(tmp_path: Path) -> None:
    named = _credential(tmp_path, "named", ["named.test", "extra.test"], "ec")
    default = _credential(tmp_path, "default", ["default.test"], "rsa")
    with _proxy(
        tmp_path,
        [_server("named", ["named.test"], [named]), _server("default", [], [default])],
    ) as port:
        for name, expected in [
            ("named.test", named),
            ("extra.test", default),
            ("unknown.test", default),
            (None, default),
        ]:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
                with _context().wrap_socket(tcp, server_hostname=name) as tls:
                    assert tls.getpeercert(binary_form=True) == expected.der


def test_tls_coverage_failure_exits_before_starting_workers_or_listening(
    tmp_path: Path,
) -> None:
    certificate = _credential(tmp_path, "wrong", ["different.test"], "ec")
    port = get_unique_port()
    config: ConfigDict = {
        "listeners": [
            {"name": "main", "kind": "https", "addresses": [f"127.0.0.1:{port}"]}
        ],
        "plugins": {"echo": {}},
        "services": [{"name": "direct", "kind": "echo.echo"}],
        "servers": [_server("broken", ["uncovered.test"], [certificate])],
    }
    path = tmp_path / "invalid.yaml"
    _ = path.write_text(dict_to_yaml(config))
    result = subprocess.run(
        [NEOPROXY_BINARY, "--config", str(path)],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert result.returncode == 1
    assert b"uncovered.test" in result.stderr
    assert b"broken" in result.stderr
    assert str(certificate.cert).encode() in result.stderr
    assert not (tmp_path / "logs").exists()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", port))


@pytest.mark.parametrize("kind", ["https", "http3"])
def test_default_server_proxies_connect_target_independently_of_tls_name(
    tmp_path: Path, kind: Literal["https", "http3"]
) -> None:
    credential = _credential(tmp_path, "proxy", ["proxy.test"], "rsa")
    with _proxy(tmp_path, [_server("forward", [], [credential])], kind) as port:

        async def exercise() -> None:
            async def echo(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                try:
                    while data := await reader.read(65536):
                        writer.write(data)
                        await writer.drain()
                finally:
                    await close_writer(writer)

            target_port = get_unique_port()
            server = await asyncio.start_server(echo, "127.0.0.1", target_port)
            async with server, asyncio.timeout(6):
                payload = b"forward-proxy\x00\xff" * 1000
                if kind == "https":
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port, ssl=_context(), server_hostname="proxy.test"
                    )
                    try:
                        writer.write(
                            (
                                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                                + f"Host: 127.0.0.1:{target_port}\r\n\r\n"
                            ).encode()
                        )
                        await writer.drain()
                        assert (await reader.readuntil(b"\r\n\r\n")).startswith(
                            b"HTTP/1.1 200 "
                        )
                        writer.write(payload)
                        await writer.drain()
                        assert await reader.readexactly(len(payload)) == payload
                    finally:
                        await close_writer(writer)
                else:
                    configuration = QuicConfiguration(
                        is_client=True, alpn_protocols=["h3"]
                    )
                    configuration.server_name = "proxy.test"
                    configuration.load_verify_locations(str(credential.cert))
                    async with connect(
                        "127.0.0.1",
                        port,
                        configuration=configuration,
                        create_protocol=LifecycleClient,
                    ) as client:
                        assert isinstance(client, LifecycleClient)
                        stream = client.request(
                            b"CONNECT", f"127.0.0.1:{target_port}".encode()
                        )
                        client.http.send_data(stream, payload, end_stream=True)
                        client.transmit()
                        await client.read_data(stream, payload)
                        _ = await client.read_end(stream)

        asyncio.run(exercise())


def test_tls_and_http_server_selection_stay_within_the_current_listener(
    tmp_path: Path,
) -> None:
    first = _credential(tmp_path, "first", ["a.test", "b.test"], "ec")
    second = _credential(tmp_path, "second", ["a.test", "b.test"], "rsa")
    ports = [get_unique_port(), get_unique_port()]
    a = _server("a", ["a.test"], [first])
    b = _server("b", ["b.test"], [second])
    b["listeners"] = ["other"]
    config: ConfigDict = {
        "server_threads": 2,
        "plugins": {"echo": {}},
        "services": [{"name": "direct", "kind": "echo.echo"}],
        "listeners": [
            {"name": "main", "kind": "https", "addresses": [f"127.0.0.1:{ports[0]}"]},
            {"name": "other", "kind": "https", "addresses": [f"127.0.0.1:{ports[1]}"]},
        ],
        "servers": [a, b],
    }
    path = tmp_path / "isolated.yaml"
    _ = path.write_text(dict_to_yaml(config))
    process = start_proxy(str(path))
    try:
        for port, name, other, credential in [
            (ports[0], "a.test", "b.test", first),
            (ports[1], "b.test", "a.test", second),
        ]:
            assert process.wait_ready()
            with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
                with _context().wrap_socket(tcp, server_hostname=name) as tls:
                    assert tls.getpeercert(binary_form=True) == credential.der
                    tls.sendall(
                        (
                            f"GET / HTTP/1.1\r\nHost: {other}\r\n"
                            + "Connection: close\r\n\r\n"
                        ).encode()
                    )
                    assert tls.recv(4096).startswith(b"HTTP/1.1 404 ")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
                try:
                    tls = _context().wrap_socket(tcp, server_hostname=other)
                except ssl.SSLError:
                    pass
                else:
                    tls.close()
                    pytest.fail("SNI selected a server from a different listener")
    finally:
        terminate_process(process)
    assert process.returncode == 0
