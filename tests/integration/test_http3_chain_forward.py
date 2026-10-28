"""H3 chain validation and server-side deadlines.

Successful GET/HEAD/POST and CONNECT dispatch belong to chain_matrix_local.
These cases retain malformed-target rejection and require an actual proxy error
when QUIC cannot connect, rather than accepting curl's own timeout as success.
"""

import socket
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.configuration import ConfigDict, StringMap
from tests.fixtures.http_request import send_raw_request
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port


def _configuration(ca: str, relay_port: int) -> ConfigDict:
    return {
        "server_threads": 1,
        "plugins": {
            "upstream": {
                "upstreams": [
                    {
                        "name": "relay",
                        "addresses": [
                            {
                                "address": f"127.0.0.1:{relay_port}",
                                "hostname": "localhost",
                                "address_protocol": "http3",
                            }
                        ],
                    }
                ],
                "connection_pools": [
                    {
                        "name": "default",
                        "certificates": {"server_ca_path": ca},
                        "quic_connection_connect_timeout": "100ms",
                    }
                ],
            }
        },
        "listeners": [{"name": "main", "kind": "http"}],
        "services": [
            {"name": "relay", "kind": "upstream.upstream", "upstream": "relay"}
        ],
        "servers": [{"name": "main", "listeners": ["main"], "service": "relay"}],
    }


def test_chain_rejects_invalid_targets_without_contacting_upstream(
    tmp_path: Path, shared_test_certs: StringMap
) -> None:
    relay_port = get_unique_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
        relay.bind(("127.0.0.1", relay_port))
        with running_proxy(
            tmp_path,
            _configuration(shared_test_certs["ca_path"], relay_port),
        ) as proxy:
            for target in (b"/", b"ftp://example.test/"):
                response = send_raw_request(
                    "127.0.0.1",
                    proxy.port,
                    b"GET " + target + b" HTTP/1.1\r\nHost: example.test\r\n\r\n",
                )
                assert response.split(b"\r\n", 1)[0].split()[1] == b"400"
                assert proxy.process.poll() is None
            relay.settimeout(0.05)
            try:
                datagram = relay.recv(65535)
            except TimeoutError:
                datagram = b""
            assert datagram == b"", "invalid requests must not reach the relay"


@pytest.mark.parametrize("method", ["GET", "POST", "CONNECT"])
def test_chain_unreachable_upstream_returns_timeout_response(
    tmp_path: Path,
    shared_test_certs: StringMap,
    method: Literal["GET", "POST", "CONNECT"],
) -> None:
    # A bound, silent UDP peer gives a deterministic QUIC handshake timeout,
    # independent of external routing and ICMP port-unreachable behavior.
    relay_port = get_unique_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
        relay.bind(("127.0.0.1", relay_port))
        with running_proxy(
            tmp_path,
            _configuration(shared_test_certs["ca_path"], relay_port),
        ) as proxy:
            target = (
                "example.test:80" if method == "CONNECT" else "http://example.test/"
            )
            response = send_raw_request(
                "127.0.0.1",
                proxy.port,
                (
                    f"{method} {target} HTTP/1.1\r\nHost: example.test:80\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n"
                ).encode(),
                timeout=2,
            )
            assert response.split(b"\r\n", 1)[0].split()[1] == b"504", response
            assert b"error=connection_timeout" in response.lower()
            relay.settimeout(1)
            assert relay.recv(65535), "the proxy must attempt the QUIC handshake"
            assert proxy.process.poll() is None
