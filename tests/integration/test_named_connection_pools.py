"""Named connection resources isolate DNS, TLS identities and cached transports."""

import socket
import ssl
from pathlib import Path
from typing import Literal

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from tests.fixtures.certificates import generate_client_cert, generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.discovery_dns import discovery_dns
from tests.fixtures.discovery_scenario import curl_forward
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import TargetServerFactory


def configuration(protocol: str, port: int, pools: list[ConfigDict]) -> ConfigDict:
    return {
        "server_threads": 4,
        "plugins": {
            "upstream": {
                "use_connection_pool": "a",
                "connection_pools": list(pools),
                "upstreams": [
                    {
                        "name": "relay",
                        "addresses": [
                            {
                                "address": f"peer.test:{port}",
                                "address_protocol": protocol,
                            },
                            {
                                "address": f"peer.test:{port}",
                                "address_protocol": protocol,
                                "use_connection_pool": "b",
                            },
                        ],
                    }
                ],
            }
        },
        "listeners": [{"name": "main", "kind": "http"}],
        "services": [
            {"name": "relay", "kind": "upstream.upstream", "upstream": "relay"}
        ],
        "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["https", "http3"])
async def test_named_connection_pools_isolate_cached_connections_and_dns(
    tmp_path: Path, protocol: Literal["https", "http3"]
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["peer.test"]
    )
    async with (
        origin_peer(
            PeerConfig(
                certificate=cert, key=key, wire="h3" if protocol == "http3" else "h1"
            )
        ) as peer,
        discovery_dns() as a,
        discovery_dns() as b,
    ):
        pools: list[ConfigDict] = [
            {
                "name": name,
                "dns_servers": [f"127.0.0.1:{dns.port}"],
                "certificates": {"server_ca_path": ca},
                "http3_pool_max_connections_per_host": 1,
            }
            for name, dns in [("a", a), ("b", b)]
        ]
        with running_proxy(
            tmp_path, configuration(protocol, peer.port, pools)
        ) as proxy:
            for _ in range(6):
                assert (await curl_forward(proxy.port, "http://target.test/"))[0] == 200
            connections = [request.connection for request in peer.requests]
            assert len(set(connections)) == 2
            assert connections[::2] == [connections[0]] * 3
            assert connections[1::2] == [connections[1]] * 3
            assert len(a.queries) == len(b.queries) == 2


@pytest.mark.asyncio
async def test_named_connection_pools_use_independent_dns_answers_and_trust(
    tmp_path: Path,
) -> None:
    a_dir, b_dir = tmp_path / "a", tmp_path / "b"
    a_dir.mkdir()
    b_dir.mkdir()
    cert_a, key_a, ca_a, _ = generate_test_certificates(
        str(a_dir), san_entries=["peer.test"]
    )
    cert_b, key_b, ca_b, _ = generate_test_certificates(
        str(b_dir), san_entries=["peer.test"]
    )
    async with (
        origin_peer(PeerConfig(certificate=cert_a, key=key_a, wire="h1")) as first,
        origin_peer(
            PeerConfig(
                certificate=cert_b, key=key_b, wire="h1", host="::1", port=first.port
            )
        ) as second,
        discovery_dns() as a,
        discovery_dns() as b,
    ):
        b.addresses = ("::1",)
        pools: list[ConfigDict] = [
            {
                "name": name,
                "dns_servers": [f"127.0.0.1:{dns.port}"],
                "certificates": {"server_ca_path": ca},
            }
            for name, dns, ca in [("a", a, ca_a), ("b", b, ca_b)]
        ]
        with running_proxy(
            tmp_path, configuration("https", first.port, pools)
        ) as proxy:
            for _ in range(6):
                assert (await curl_forward(proxy.port, "http://target.test/"))[0] == 200
            assert len(first.requests) == len(second.requests) == 3
            assert len(a.queries) == len(b.queries) == 2


@pytest.mark.asyncio
async def test_named_connection_pools_keep_client_certificate_identity(
    tmp_path: Path, target_server: TargetServerFactory
) -> None:
    cert, key, ca, ca_key = generate_test_certificates(
        str(tmp_path), san_entries=["peer.test"]
    )
    identities = [
        generate_client_cert(str(tmp_path), ca, ca_key, name)
        for name in ["client-a", "client-b"]
    ]
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    tls.load_verify_locations(cafile=ca)
    tls.verify_mode = ssl.CERT_REQUIRED
    port = get_unique_port()

    def peer(raw: socket.socket) -> None:
        with raw, tls.wrap_socket(raw, server_side=True) as conn:
            conn.settimeout(6)
            der = conn.getpeercert(binary_form=True)
            assert der is not None
            certificate = x509.load_der_x509_certificate(der)
            identity = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value
            assert isinstance(identity, str)
            payload = identity.encode()
            while True:
                headers = b""
                while b"\r\n\r\n" not in headers:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    headers += chunk
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(payload)).encode()
                    + b"\r\n\r\n"
                    + payload
                )

    _ = target_server(port, peer)
    async with discovery_dns() as dns:
        pools: list[ConfigDict] = [
            {
                "name": name,
                "dns_servers": [f"127.0.0.1:{dns.port}"],
                "certificates": {
                    "server_ca_path": ca,
                    "client_cert_path": pair[0],
                    "client_key_path": pair[1],
                },
            }
            for name, pair in zip(["a", "b"], identities, strict=True)
        ]
        with running_proxy(tmp_path, configuration("https", port, pools)) as proxy:
            for expected in [b"client-a", b"client-b"] * 3:
                status, _, body = await curl_forward(proxy.port, "http://target.test/")
                assert status == 200
                assert body == expected
