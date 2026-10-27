"""Exercise both NeoProxy H3 adapters with bulk data and TCP half-closes."""

import asyncio
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.configuration import StringMap
from tests.fixtures.h3_configuration import (
    create_http3_chain_config,
    create_http3_listener_config,
)
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer

type HalfClose = Literal["upload", "download"]


async def _exercise_half_close(port: int, half_close: HalfClose) -> None:
    upload = b"".join(
        index.to_bytes(4, "big") + bytes(range(256)) for index in range(4097)
    )
    download = b"".join(
        index.to_bytes(4, "big") + bytes(reversed(range(256)))
        for index in reversed(range(4099))
    )
    finished = asyncio.Event()

    async def target(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            if half_close == "upload":
                assert await reader.read() == upload
            writer.write(download)
            await writer.drain()
            writer.write_eof()
            await writer.drain()
            if half_close == "download":
                assert await reader.read() == upload
            finished.set()
        finally:
            await close_writer(writer)

    async with asyncio.timeout(12), asyncio.TaskGroup() as tasks:

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            _ = tasks.create_task(target(reader, writer))

        target_port = get_unique_port()
        server = await asyncio.start_server(accept, "127.0.0.1", target_port)
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(
                    (
                        f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                        + f"Host: 127.0.0.1:{target_port}\r\n\r\n"
                    ).encode()
                )
                await writer.drain()
                headers = await reader.readuntil(b"\r\n\r\n")
                assert headers.startswith(b"HTTP/1.1 200 "), headers
                if half_close == "download":
                    # Receiving FIN must leave the upload half usable.
                    assert await reader.read() == download
                for offset in range(0, len(upload), 10003):
                    writer.write(upload[offset : offset + 10003])
                    await writer.drain()
                writer.write_eof()
                await writer.drain()
                if half_close == "upload":
                    # This tail is produced only after the target sees
                    # the upload FIN, so early full close loses it.
                    assert await reader.read() == download
                _ = await finished.wait()
            finally:
                await close_writer(writer)


@pytest.mark.parametrize("half_close", ["upload", "download"])
def test_h3_chain_preserves_bulk_data_and_independent_half_closes(
    tmp_path: Path, shared_test_certs: StringMap, half_close: HalfClose
) -> None:
    relay_dir = tmp_path / "relay"
    entry_dir = tmp_path / "entry"
    relay_dir.mkdir()
    entry_dir.mkdir()
    relay_port = get_unique_port()
    entry_port = get_unique_port()
    relay_config = create_http3_listener_config(
        relay_port,
        shared_test_certs["cert_path"],
        shared_test_certs["key_path"],
        str(relay_dir),
    )
    entry_config = create_http3_chain_config(
        entry_port,
        [("127.0.0.1", relay_port, 1)],
        shared_test_certs["ca_path"],
        str(entry_dir),
    )
    relay = start_proxy(relay_config)
    try:
        assert relay.wait_ready(timeout=3)
        entry = start_proxy(entry_config)
        try:
            assert entry.wait_ready(timeout=3)
            # Both client/server H3 adapters run in real proxy processes.
            # The dependency's classic CONNECT pseudo-header defect has
            # its own strict-peer failure case in test_dependency_h3.py.
            asyncio.run(_exercise_half_close(entry_port, half_close))
        finally:
            terminate_process(entry)
        assert entry.returncode == 0
    finally:
        terminate_process(relay)
    assert relay.returncode == 0
