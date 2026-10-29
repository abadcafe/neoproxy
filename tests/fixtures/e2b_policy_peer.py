"""module: e2b_policy_peer; responsibility: observe conditional policy API exchanges.
Public operations: PolicyReply, ApiRequest, PolicyApi, policy_api.
Data entities: those types. Tests: integration/test_e2b_policy.py.
"""

import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, Field

from .configuration import ConfigDict
from .ports import get_unique_port
from .stream_cleanup import close_writer


class PolicyReply(BaseModel):
    status: int = 200
    version: int = 1
    ttl: int = 60
    policy: ConfigDict = Field(default_factory=dict)
    sandbox_id: str | None = None
    invalid_body: bool = False
    omit_etag: bool = False


@dataclass(frozen=True)
class ApiRequest:
    sandbox_id: str
    etag: str | None


@dataclass
class PolicyApi:
    port: int
    replies: dict[str, PolicyReply] = field(default_factory=dict)
    requests: list[ApiRequest] = field(default_factory=list)
    arrived: asyncio.Queue[ApiRequest] = field(
        default_factory=asyncio.Queue[ApiRequest]
    )
    gate: asyncio.Event | None = None


@asynccontextmanager
async def policy_api() -> AsyncGenerator[PolicyApi]:
    api = PolicyApi(get_unique_port())
    tasks: list[asyncio.Task[None]] = []

    async def exchange(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
            lines = raw.decode().split("\r\n")
            path = lines[0].split(" ")[1]
            query = parse_qs(urlsplit(path).query)
            sandbox = query["sandbox_id"][0]
            headers = {
                name.lower(): value.strip()
                for line in lines[1:]
                if ":" in line
                for name, _, value in [line.partition(":")]
            }
            request = ApiRequest(sandbox, headers.get("if-none-match"))
            api.requests.append(request)
            api.arrived.put_nowait(request)
            if api.gate is not None:
                _ = await api.gate.wait()
            reply = api.replies.get(sandbox, PolicyReply())
            body = (
                b"invalid"
                if reply.invalid_body
                else json.dumps(
                    {"sandbox_id": reply.sandbox_id or sandbox, "policy": reply.policy}
                ).encode()
            )
            if reply.status == 304:
                body = b""
            etag = "" if reply.omit_etag else f'ETag: "{reply.version}"\r\n'
            writer.write(
                (
                    f"HTTP/1.1 {reply.status} Policy\r\n{etag}"
                    f"X-Policy-TTL: {reply.ttl}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode()
                + body
            )
            await writer.drain()
        except asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError:
            pass
        finally:
            await close_writer(writer)

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        tasks.append(asyncio.create_task(exchange(reader, writer)))

    server = await asyncio.start_server(accept, "127.0.0.1", api.port)
    try:
        yield api
    finally:
        server.close()
        for task in tasks:
            if not task.done():
                _ = task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        await server.wait_closed()
        for result in results:
            assert result is None or isinstance(result, asyncio.CancelledError), result
