"""module: socks5_upstream; responsibility: observe SOCKS5 upstream exchanges.
Public operations: socks_peer, SocksPeer, curl_tunnel, configuration.
Data entities: SocksPeer. Tests: integration/test_socks5_upstream.py.
"""

import asyncio
import subprocess
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from .configuration import ConfigDict
from .curl import get_curl_env_without_no_proxy
from .ports import get_unique_port
from .stream_cleanup import close_writer


@dataclass
class SocksPeer:
    port: int
    method: int = 0
    auth_status: int = 0
    reply: int = 0
    delay: float = 0
    disconnect: bool = False
    connections: int = 0
    methods: list[bytes] = field(default_factory=list)
    users: list[tuple[bytes, bytes]] = field(default_factory=list)
    targets: list[tuple[int, bytes, int]] = field(default_factory=list)


@asynccontextmanager
async def socks_peer() -> AsyncGenerator[SocksPeer]:
    peer = SocksPeer(get_unique_port())
    tasks: list[asyncio.Task[None]] = []

    async def exchange(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer.connections += 1
        try:
            if peer.disconnect:
                return
            version, count = await reader.readexactly(2)
            assert version == 5
            peer.methods.append(await reader.readexactly(count))
            await asyncio.sleep(peer.delay)
            writer.write(bytes([5, peer.method]))
            await writer.drain()
            if peer.method == 255:
                return
            if peer.method == 2:
                version, count = await reader.readexactly(2)
                assert version == 1
                username = await reader.readexactly(count)
                count = (await reader.readexactly(1))[0]
                password = await reader.readexactly(count)
                peer.users.append((username, password))
                writer.write(bytes([1, peer.auth_status]))
                await writer.drain()
                if peer.auth_status:
                    return
            version, command, reserved, kind = await reader.readexactly(4)
            assert (version, command, reserved) == (5, 1, 0)
            count = (
                (await reader.readexactly(1))[0] if kind == 3 else {1: 4, 4: 16}[kind]
            )
            host = await reader.readexactly(count)
            port = int.from_bytes(await reader.readexactly(2), "big")
            peer.targets.append((kind, host, port))
            writer.write(bytes([5, peer.reply, 0, 1, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            if peer.reply:
                return
            _ = await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                + b"Connection: close\r\n\r\nsocks"
            )
            await writer.drain()
        except asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError:
            pass
        finally:
            await close_writer(writer)

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        tasks.append(asyncio.create_task(exchange(reader, writer)))

    server = await asyncio.start_server(accept, "127.0.0.1", peer.port)
    try:
        yield peer
    finally:
        server.close()
        await server.wait_closed()
        for task in tasks:
            if not task.done():
                _ = task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            assert result is None or isinstance(result, asyncio.CancelledError), result


def configuration(
    addresses: list[ConfigDict], user: ConfigDict | None = None
) -> ConfigDict:
    plugin: ConfigDict = {
        "address_protocol": "socks5",
        "address_fail_timeout": "30s",
        "upstream_request_timeout": "200ms",
        "tcp_keep_alive_time": "30s",
        "tcp_keep_alive_interval": "5s",
        "tcp_keep_alive_retries": 3,
        "upstreams": [{"name": "main", "addresses": list(addresses)}],
    }
    if user is not None:
        plugin["user"] = user
    return {
        "server_threads": 1,
        "plugins": {"upstream": plugin},
        "listeners": [{"name": "main", "kind": "http"}],
        "services": [{"name": "main", "kind": "upstream.upstream", "upstream": "main"}],
        "servers": [{"name": "main", "listeners": ["main"], "service": "main"}],
    }


async def curl_tunnel(
    entry: int, authority: str = "origin.invalid:80"
) -> tuple[int, bytes]:
    result = await asyncio.to_thread(
        subprocess.run,
        [
            "curl",
            "--silent",
            "--show-error",
            "--http1.1",
            "--noproxy",
            "",
            "--proxy",
            f"http://127.0.0.1:{entry}",
            "--proxytunnel",
            "--max-time",
            "3",
            "--write-out",
            "\n%{http_connect}",
            f"http://{authority}/",
        ],
        capture_output=True,
        timeout=5,
        env=get_curl_env_without_no_proxy(),
    )
    body, _, status = result.stdout.rpartition(b"\n")
    assert status.isdigit(), (result.stdout, result.stderr)
    code = int(status)
    assert result.returncode in ((0,) if code == 200 else (7, 56)), result.stderr
    return code, body
