"""module: discovery_dns; responsibility: serve mutable DNS A/AAAA records.
Public operations: DiscoveryDns, discovery_dns. Data entities: those types.
Tests: test_direct_http1.py.
"""

import asyncio
import ipaddress
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import override

from .ports import get_unique_port


@dataclass
class DiscoveryDns:
    port: int
    queries: list[tuple[str, int]] = field(default_factory=list)
    addresses: tuple[str, ...] = ("127.0.0.1",)
    unanswered: set[str] = field(default_factory=set)
    ttl: int = 60
    failure: bool = False
    response_delay: float = 0
    hosts: dict[str, tuple[str, ...]] = field(default_factory=dict)


def encode_name(name: str) -> bytes:
    return (
        b"".join(
            bytes([len(label)]) + label.encode()
            for label in name.rstrip(".").split(".")
            if label
        )
        + b"\x00"
    )


@asynccontextmanager
async def discovery_dns() -> AsyncGenerator[DiscoveryDns]:
    dns = DiscoveryDns(get_unique_port())

    class DnsProtocol(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.transport: asyncio.DatagramTransport | None = None

        @override
        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            assert isinstance(transport, asyncio.DatagramTransport)
            self.transport = transport

        @override
        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            cursor = 12
            labels: list[str] = []
            while length := data[cursor]:
                cursor += 1
                labels.append(data[cursor : cursor + length].decode())
                cursor += length
            cursor += 1
            name = ".".join(labels).lower()
            kind = int.from_bytes(data[cursor : cursor + 2])
            dns.queries.append((name, kind))
            if name in dns.unanswered:
                return
            answers: list[bytes] = []
            if kind in (1, 28) and not dns.failure:
                for address in dns.hosts.get(name, dns.addresses):
                    ip = ipaddress.ip_address(address)
                    if (kind == 1 and ip.version == 4) or (
                        kind == 28 and ip.version == 6
                    ):
                        answers.append(
                            encode_name(name)
                            + kind.to_bytes(2)
                            + b"\x00\x01"
                            + dns.ttl.to_bytes(4)
                            + len(ip.packed).to_bytes(2)
                            + ip.packed
                        )
            response = (
                data[:2]
                + (b"\x81\x82" if dns.failure else b"\x81\x80")
                + b"\x00\x01"
                + len(answers).to_bytes(2)
                + b"\x00\x00\x00\x00"
                + data[12 : cursor + 4]
                + b"".join(answers)
            )
            assert self.transport is not None
            if dns.response_delay:
                _ = asyncio.get_running_loop().call_later(
                    dns.response_delay, self.transport.sendto, response, addr
                )
            else:
                self.transport.sendto(response, addr)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        DnsProtocol, local_addr=("127.0.0.1", dns.port)
    )
    try:
        yield dns
    finally:
        transport.close()
