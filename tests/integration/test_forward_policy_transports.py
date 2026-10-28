"""Wire contracts for forwarding policy shared by TCP/TLS and H3 proxies."""

import asyncio
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer
from tests.fixtures.stream_cleanup import close_writer


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["https", "http3"])
async def test_forwarding_policy_is_consistent_across_proxy_transports(
    tmp_path: Path, transport: Literal["https", "http3"]
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    wire = "h1" if transport == "https" else "h3"
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire=wire)) as peer:
        config: ConfigDict = {
            "server_threads": 1,
            "plugins": {
                "upstream": {
                    "upstreams": [
                        {
                            "name": "relay",
                            "addresses": [
                                {
                                    "address": f"127.0.0.1:{peer.port}",
                                    "hostname": "localhost",
                                    "user": {"username": "alice", "password": "secret"},
                                    "address_protocol": transport,
                                }
                            ],
                        }
                    ],
                    "connection_pools": [
                        {"name": "default", "certificates": {"server_ca_path": ca}}
                    ],
                }
            },
            "listeners": [{"name": "main", "kind": "http"}],
            "services": [
                {"name": "relay", "kind": "upstream.upstream", "upstream": "relay"}
            ],
            "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
        }
        with running_proxy(tmp_path, config) as proxy:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
            try:
                writer.write(
                    b"POST http://origin.test/path?q=1 HTTP/1.1\r\n"
                    + b"Host: other.test\r\n"
                    + b"Cookie: first=a\r\nCookie: second=b\r\n"
                    + b"Proxy-Authorization: Basic cHJldmlvdXM6aG9w\r\n"
                    + b"Connection: x-private, close\r\nX-Private: remove-me\r\n"
                    + b"Via: 1.0 previous\r\nContent-Length: 7\r\n\r\npayload"
                )
                await writer.drain()
                async with asyncio.timeout(3):
                    headers = await reader.readuntil(b"\r\n\r\n")
                    assert int(headers.split()[1]) == 200
                    assert await reader.readexactly(7) == b"payload"
            finally:
                await close_writer(writer)
            assert len(peer.requests) == 1
            request = peer.requests[0]
            assert request.headers["cookie"] == "first=a; second=b"
            assert request.headers["host"] == "origin.test"
            assert request.headers["proxy-authorization"] == "Basic YWxpY2U6c2VjcmV0"
            assert "x-private" not in request.headers
            assert "1.1 neoproxy" in request.headers["via"]
            expected_via = b"3 neoproxy" if transport == "http3" else b"1.1 neoproxy"
            assert expected_via in headers.lower()
            assert b"received-status=200" in headers.lower()
