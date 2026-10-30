"""Valid SOCKS5 boundaries must reach the upstream with their exact value."""

import asyncio
import socket
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.socks5_client import (
    socks5_connect_domain,
    socks5_connect_ipv4,
    socks5_connect_ipv6,
    socks5_handshake_no_auth,
)
from tests.fixtures.socks5_protocol import AuthMethod, ReplyCode
from tests.fixtures.socks5_result import CommandReply, MethodReply
from tests.fixtures.socks5_upstream import configuration, socks_peer

type AddressKind = Literal["ipv4", "ipv6", "domain"]


def exchange(entry: int, kind: AddressKind, host: str, port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", entry), timeout=3) as client:
        assert socks5_handshake_no_auth(client) == MethodReply(AuthMethod.NONE)
        connect = {
            "ipv4": socks5_connect_ipv4,
            "ipv6": socks5_connect_ipv6,
            "domain": socks5_connect_domain,
        }[kind]
        reply = connect(client, host, port)
        assert isinstance(reply, CommandReply)
        assert reply.code is ReplyCode.SUCCESS
        client.sendall(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
        with client.makefile("rb") as received:
            return received.read()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,host,port",
    [
        ("ipv4", "127.0.0.1", 1),
        ("ipv4", "127.0.0.1", 65535),
        ("ipv6", "::1", 1),
        ("ipv6", "::1", 65535),
        ("domain", "a" * 255, 65535),
    ],
)
async def test_connect_preserves_valid_target_boundaries(
    tmp_path: Path,
    kind: AddressKind,
    host: str,
    port: int,
) -> None:
    async with socks_peer() as peer:
        config = configuration([{"address": f"127.0.0.1:{peer.port}"}])
        config["listeners"] = [{"name": "main", "kind": "socks5"}]
        with running_proxy(tmp_path, config) as proxy:
            response = await asyncio.to_thread(exchange, proxy.port, kind, host, port)
        assert response.endswith(b"socks")
        expected = (
            (1, socket.inet_pton(socket.AF_INET, host), port)
            if kind == "ipv4"
            else (4, socket.inet_pton(socket.AF_INET6, host), port)
            if kind == "ipv6"
            else (3, host.encode(), port)
        )
        assert peer.targets == [expected]
