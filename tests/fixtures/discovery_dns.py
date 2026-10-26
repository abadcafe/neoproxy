"""module: discovery_dns; responsibility: serve mutable DNS HTTPS discovery records.
Public operations: DnsRecord, DiscoveryDns, discovery_dns. Data entities: those types.
Tests: test_origin_discovery.py.
"""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import override

from pydantic import BaseModel

from .ports import get_unique_port


class DnsRecord(BaseModel):
    name: str
    priority: int = 1
    target: str = "."
    protocols: tuple[str, ...] = ("h3",)
    port: int = 443
    ttl: int = 60
    mandatory: tuple[int, ...] = ()


@dataclass
class DiscoveryDns:
    port: int
    queries: list[tuple[str, int]] = field(default_factory=list)


def encode_name(name: str) -> bytes:
    return (
        b"".join(
            bytes([len(label)]) + label.encode()
            for label in name.rstrip(".").split(".")
            if label
        )
        + b"\x00"
    )


def record_data(record: DnsRecord) -> bytes:
    parameters: dict[int, bytes] = {}
    if record.priority:
        if record.mandatory:
            parameters[0] = b"".join(key.to_bytes(2) for key in record.mandatory)
        parameters[1] = b"".join(
            bytes([len(protocol)]) + protocol.encode() for protocol in record.protocols
        )
        parameters[3] = record.port.to_bytes(2)
        for key in record.mandatory:
            if key not in parameters:
                parameters[key] = b"unknown"
    return (
        record.priority.to_bytes(2)
        + encode_name(record.target)
        + b"".join(
            key.to_bytes(2) + len(value).to_bytes(2) + value
            for key, value in sorted(parameters.items())
        )
    )


@asynccontextmanager
async def discovery_dns(records: list[DnsRecord]) -> AsyncGenerator[DiscoveryDns]:
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
            answers: list[bytes] = []
            if kind == 65:
                for record in records:
                    if record.name == name:
                        payload = record_data(record)
                        answers.append(
                            encode_name(name)
                            + b"\x00A\x00\x01"
                            + record.ttl.to_bytes(4)
                            + len(payload).to_bytes(2)
                            + payload
                        )
            elif kind == 1:
                answers.append(
                    encode_name(name)
                    + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
                )
            response = (
                data[:2]
                + b"\x81\x80\x00\x01"
                + len(answers).to_bytes(2)
                + b"\x00\x00\x00\x00"
                + data[12 : cursor + 4]
                + b"".join(answers)
            )
            assert self.transport is not None
            self.transport.sendto(response, addr)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        DnsProtocol, local_addr=("127.0.0.1", dns.port)
    )
    try:
        yield dns
    finally:
        transport.close()
