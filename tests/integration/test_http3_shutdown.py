"""Process contracts for HTTP/3 shutdown across requests, tunnels and workers."""

import asyncio
import signal
import socket
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

import pytest
from aioquic.asyncio.client import connect
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset

from tests.fixtures.certificates import generate_server_cert
from tests.fixtures.configuration import StringMap
from tests.fixtures.h3_lifecycle import LifecycleClient
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer
from tests.fixtures.udp_sockets import bound_socket_count


@contextmanager
def running_proxy(
    directory: Path, certificates: StringMap, workers: int
) -> Generator[tuple[BytesProcess, int]]:
    port = get_unique_port()
    cert_path, key_path = generate_server_cert(
        str(directory),
        certificates["ca_path"],
        certificates["ca_key_path"],
        san_entries=["localhost", "echo.test"],
        cert_name="echo-entry",
    )
    config = directory / "server.yaml"
    _ = config.write_text(f"""server_threads: {workers}
plugins:
  echo: {{}}
  upstream:
    upstreams:
    - name: direct
listeners:
- name: main
  kind: http3
  addresses: ["127.0.0.1:{port}"]
services:
- name: echo
  kind: echo.echo
- name: direct
  kind: upstream.upstream
  args:
    upstream: direct
servers:
- name: echo
  hostnames: [localhost, echo.test]
  service: echo
  listeners: [main]
  tls:
    certificates:
    - cert_path: {cert_path}
      key_path: {key_path}
- name: proxy
  service: direct
  listeners: [main]
""")
    process = start_proxy(str(config))
    try:
        deadline = time.monotonic() + 3
        while bound_socket_count(process, port) != workers:
            assert process.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.02)
        yield process, port
    finally:
        terminate_process(process, force=True)


def configuration(certificates: StringMap) -> QuicConfiguration:
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.server_name = "localhost"
    config.load_verify_locations(certificates["ca_path"])
    return config


@pytest.mark.parametrize("workers", [1, 4])
def test_shutdown_sends_goaway_and_releases_cooperative_idle_connection(
    tmp_path: Path, shared_test_certs: StringMap, workers: int
) -> None:
    with running_proxy(tmp_path, shared_test_certs, workers) as (process, port):

        async def exercise() -> None:
            async with connect(
                "127.0.0.1",
                port,
                configuration=configuration(shared_test_certs),
                create_protocol=LifecycleClient,
            ) as client:
                assert isinstance(client, LifecycleClient)
                _ = await asyncio.wait_for(client.settings_received.wait(), timeout=2)
                process.send_signal(signal.SIGTERM)
                assert await client.goaway() == 0
                rejected = client.incomplete_request()
                event = await client.next_event(rejected)
                assert isinstance(event, StreamReset), event
                assert event.error_code == 0x10B
                # The idle client closes after GOAWAY. This must finish
                # promptly, without consuming the 3s cancellation grace.

        asyncio.run(exercise())
        assert process.wait(timeout=2) == 0


@pytest.mark.parametrize("workers", [1, 4])
def test_shutdown_bounds_transport_wait_when_client_keeps_connection_open(
    tmp_path: Path, shared_test_certs: StringMap, workers: int
) -> None:
    with running_proxy(tmp_path, shared_test_certs, workers) as (process, port):

        async def exercise() -> None:
            async with connect(
                "127.0.0.1",
                port,
                configuration=configuration(shared_test_certs),
                create_protocol=LifecycleClient,
            ) as client:
                assert isinstance(client, LifecycleClient)
                stream = client.request(b"POST")
                client.http.send_data(stream, b"complete", end_stream=True)
                client.transmit()
                await client.read_data(stream, b"complete")
                _ = await client.read_end(stream)
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                assert await client.goaway() == stream + 4
                _ = await asyncio.wait_for(client.closed.wait(), timeout=6)
                assert 2.5 <= time.monotonic() - started < 6

        asyncio.run(exercise())
        assert process.wait(timeout=2) == 0


async def wait_for_idle_workers(directory: Path, count: int) -> None:
    deadline = time.monotonic() + 1.5
    while True:
        completed = sum(
            path.read_text().count("business shutdown complete")
            for path in (directory / "logs").glob("neoproxy.log*")
        )
        assert completed <= count
        if completed == count:
            return
        assert time.monotonic() < deadline, "idle workers did not finish cleanup"
        await asyncio.sleep(0.01)


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_shutdown_completes_upload_and_trailers_and_rejects_new_requests(
    tmp_path: Path, shared_test_certs: StringMap, workers: int
) -> None:
    with running_proxy(tmp_path, shared_test_certs, workers) as (process, port):

        async def exercise() -> None:
            async with connect(
                "127.0.0.1",
                port,
                configuration=configuration(shared_test_certs),
                create_protocol=LifecycleClient,
            ) as client:
                assert isinstance(client, LifecycleClient)
                stream = client.request(b"POST")
                client.http.send_data(stream, b"first", end_stream=False)
                client.transmit()
                await client.read_data(stream, b"first")
                process.send_signal(signal.SIGTERM)
                assert await client.goaway() == stream + 4
                await wait_for_idle_workers(tmp_path, workers - 1)
                assert bound_socket_count(process, port) == workers
                # Even incomplete HEADERS arriving after GOAWAY must be
                # rejected without waiting for header parsing or calling Service.
                rejected = client.incomplete_request()
                reset = await client.next_event(rejected)
                assert isinstance(reset, StreamReset)
                assert reset.error_code == 0x10B
                client.http.send_data(stream, b"last!", end_stream=False)
                trailers = [(b"x-checksum", b"complete")]
                client.http.send_headers(stream, trailers, end_stream=True)
                client.transmit()
                await client.read_data(stream, b"last!")
                assert await client.read_end(stream) == trailers

        asyncio.run(exercise())
        assert process.wait(timeout=5) == 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", port))


@pytest.mark.parametrize("workers", [1, 4])
@pytest.mark.parametrize("method", [b"GET", b"POST"])
def test_shutdown_delivers_response_tail_before_closing(
    tmp_path: Path,
    shared_test_certs: StringMap,
    workers: int,
    method: Literal[b"GET", b"POST"],
) -> None:
    with running_proxy(tmp_path, shared_test_certs, workers) as (process, port):

        async def exercise() -> None:
            release = asyncio.Event()
            tail = b"response-tail\x00\xff" * 4096

            async def target(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                try:
                    _ = await reader.readuntil(b"\r\n\r\n")
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {5 + len(tail)}\r\n\r\n".encode()
                        + b"first"
                    )
                    await writer.drain()
                    _ = await release.wait()
                    writer.write(tail)
                    await writer.drain()
                finally:
                    await close_writer(writer)

            target_port = get_unique_port()
            server = await asyncio.start_server(target, "127.0.0.1", target_port)
            async with server:
                async with connect(
                    "127.0.0.1",
                    port,
                    configuration=configuration(shared_test_certs),
                    create_protocol=LifecycleClient,
                ) as client:
                    assert isinstance(client, LifecycleClient)
                    stream = client.request(
                        method, f"127.0.0.1:{target_port}".encode(), scheme=b"http"
                    )
                    client.http.send_data(stream, b"", end_stream=True)
                    client.transmit()
                    await client.read_data(stream, b"first")
                    process.send_signal(signal.SIGTERM)
                    assert await client.goaway() == stream + 4
                    await wait_for_idle_workers(tmp_path, workers - 1)
                    assert bound_socket_count(process, port) == workers
                    assert not client.closed.is_set()
                    release.set()
                    await client.read_data(stream, tail)
                    _ = await client.read_end(stream)

        asyncio.run(exercise())
        assert process.wait(timeout=5) == 0


@pytest.mark.parametrize("workers", [1, 4])
def test_shutdown_cancels_stalled_request_at_listener_deadline(
    tmp_path: Path, shared_test_certs: StringMap, workers: int
) -> None:
    with running_proxy(tmp_path, shared_test_certs, workers) as (process, port):

        async def exercise() -> None:
            async with connect(
                "127.0.0.1",
                port,
                configuration=configuration(shared_test_certs),
                create_protocol=LifecycleClient,
            ) as client:
                assert isinstance(client, LifecycleClient)
                incomplete = client.incomplete_request()
                stream = client.request(b"POST")
                client.http.send_data(stream, b"first", end_stream=False)
                client.transmit()
                await client.read_data(stream, b"first")
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                _ = await client.goaway()
                event = await client.next_event(stream)
                assert isinstance(event, StreamReset), event
                assert event.error_code == 0x10C
                incomplete_event = await client.next_event(incomplete)
                assert isinstance(incomplete_event, StreamReset), incomplete_event
                assert incomplete_event.error_code == 0x10C
                assert 2.5 <= time.monotonic() - started < 6

        asyncio.run(exercise())
        assert process.wait(timeout=5) == 0


@pytest.mark.parametrize("workers", [1, 4])
def test_shutdown_keeps_mixed_connection_until_service_stops_tunnel(
    tmp_path: Path, shared_test_certs: StringMap, workers: int
) -> None:
    with running_proxy(tmp_path, shared_test_certs, workers) as (process, port):

        async def exercise() -> None:
            target_closed = asyncio.Event()

            async def target(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                try:
                    writer.write(await reader.readexactly(4))
                    await writer.drain()
                    assert await reader.read() == b""
                    target_closed.set()
                finally:
                    await close_writer(writer)

            target_port = get_unique_port()
            server = await asyncio.start_server(target, "127.0.0.1", target_port)
            async with server:
                async with connect(
                    "127.0.0.1",
                    port,
                    configuration=configuration(shared_test_certs),
                    create_protocol=LifecycleClient,
                ) as client:
                    assert isinstance(client, LifecycleClient)
                    tunnel = client.request(
                        b"CONNECT", f"127.0.0.1:{target_port}".encode()
                    )
                    response = await client.next_event(tunnel)
                    assert isinstance(response, HeadersReceived)
                    assert (b":status", b"200") in response.headers
                    client.http.send_data(tunnel, b"ping", end_stream=False)
                    client.transmit()
                    await client.read_data(tunnel, b"ping")
                    upload = client.request(b"POST")
                    client.http.send_data(upload, b"first", end_stream=False)
                    client.transmit()
                    await client.read_data(upload, b"first")
                    process.send_signal(signal.SIGTERM)
                    assert await client.goaway() == upload + 4
                    assert not target_closed.is_set()
                    assert not client.closed.is_set()
                    client.http.send_data(upload, b"last!", end_stream=True)
                    client.transmit()
                    await client.read_data(upload, b"last!")
                    _ = await client.read_end(upload)
                    async with asyncio.timeout(2):
                        _ = await target_closed.wait()
                    # Do not send tunnel EOF. Service shutdown must stop it.
                    event = await client.next_event(tunnel)
                    assert (
                        isinstance(event, (StreamReset, ConnectionTerminated))
                        or (
                            isinstance(event, (HeadersReceived, DataReceived))
                            and event.stream_ended
                        )
                        or (isinstance(event, StreamDataReceived) and event.end_stream)
                    )

        asyncio.run(exercise())
        assert process.wait(timeout=5) == 0
