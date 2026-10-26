"""HTTP and HTTPS targets share forwarding across direct and chained routes."""

import asyncio
import base64
import ssl
from pathlib import Path
from typing import Literal

import pytest
from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

from tests.fixtures.certificates import generate_server_cert, generate_test_certificates
from tests.fixtures.forward_scenario import ForwardNode, ProxyKind, write_forward_node
from tests.fixtures.h3_lifecycle import LifecycleClient
from tests.fixtures.ports import (
    get_unique_port,
    wait_for_proxy,
    wait_for_udp_port_bound,
)
from tests.fixtures.proxy_process import managed_processes
from tests.fixtures.stream_cleanup import close_writer

type OriginRequest = tuple[bytes, dict[bytes, bytes], bytes]
type Scheme = Literal["http", "https"]
type Method = Literal["GET", "POST"]


async def _response(reader: asyncio.StreamReader) -> tuple[int, bytes, bytes]:
    headers = await reader.readuntil(b"\r\n\r\n")
    status = int(headers.split(b" ", 2)[1])
    length = next(
        int(line.split(b":", 1)[1])
        for line in headers.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    return status, headers, await reader.readexactly(length)


async def _exchange(
    entry: int, target: str, method: Method, payload: bytes
) -> tuple[int, bytes, bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", entry)
    try:
        writer.write(
            f"{method} {target} HTTP/1.1\r\nHost: {target.split('/')[2]}\r\n".encode()
            + b"Proxy-Authorization: Basic "
            + base64.b64encode(b"entry:secret")
            + f"\r\nContent-Length: {len(payload)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + payload
        )
        await writer.drain()
        async with asyncio.timeout(5):
            return await _response(reader)
    finally:
        await close_writer(writer)


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize(
    "chain",
    [(), ("http",), ("https",), ("http3",), ("http3", "https")],
    ids=["direct", "http-proxy", "https-proxy", "h3-proxy", "mixed-two-proxies"],
)
def test_forward_preserves_target_and_message_across_proxy_routes(
    tmp_path: Path, method: Method, scheme: Scheme, chain: tuple[ProxyKind, ...]
) -> None:
    certificate, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["127.0.0.1", "proxy.test"]
    )
    origin_port = get_unique_port()
    payload = b"post-body\x00\xff" if method == "POST" else b""
    received: asyncio.Queue[OriginRequest] = asyncio.Queue()

    async def exercise() -> None:
        async def origin(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                headers = await reader.readuntil(b"\r\n\r\n")
                lines = headers.split(b"\r\n")
                fields: dict[bytes, bytes] = {}
                for line in lines[1:]:
                    name, separator, value = line.partition(b":")
                    if separator:
                        name = name.lower()
                        fields[name] = (
                            fields[name] + b", " + value.strip()
                            if name in fields
                            else value.strip()
                        )
                body = await reader.readexactly(
                    int(fields.get(b"content-length", b"0"))
                )
                received.put_nowait((lines[0], fields, body))
                writer.write(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 9\r\n\r\nforwarded"
                )
                await writer.drain()
            finally:
                await close_writer(writer)

        context: ssl.SSLContext | None = None
        if scheme == "https":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
        server = await asyncio.start_server(
            origin, "127.0.0.1", origin_port, ssl=context
        )
        async with server:
            with managed_processes() as start:
                upstream_port: int | None = None
                upstream_kind: ProxyKind = "http"
                for index, listener in reversed(list(enumerate(("http", *chain)))):
                    port = get_unique_port()
                    username = "entry" if index == 0 else f"relay{index}"
                    node = ForwardNode(
                        port=port,
                        listener=listener,
                        ca=ca,
                        certificate=certificate,
                        key=key,
                        upstream_port=upstream_port,
                        upstream_kind=upstream_kind,
                        username=username,
                        upstream_username=f"relay{index + 1}"
                        if upstream_port
                        else None,
                    )
                    process = start(write_forward_node(tmp_path / f"node{index}", node))
                    wait = (
                        wait_for_udp_port_bound
                        if listener == "http3"
                        else wait_for_proxy
                    )
                    assert wait("127.0.0.1", port, timeout=3, proc=process)
                    upstream_port, upstream_kind = port, listener
                assert upstream_port is not None
                status, _, body = await _exchange(
                    upstream_port,
                    f"{scheme}://127.0.0.1:{origin_port}/resource?q=1",
                    method,
                    payload,
                )
                assert status == 201
                assert body == b"forwarded"
                line, headers, actual_body = received.get_nowait()
                assert line == f"{method} /resource?q=1 HTTP/1.1".encode()
                assert headers[b"host"] == f"127.0.0.1:{origin_port}".encode()
                assert b"proxy-authorization" not in headers
                assert actual_body == payload
                assert len(headers[b"via"].split(b",")) == len(chain) + 1

    asyncio.run(exercise())


def test_direct_https_pool_reuses_origin_and_isolates_scheme(tmp_path: Path) -> None:
    certificate, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["127.0.0.1"]
    )
    origin_port, entry = get_unique_port(), get_unique_port()
    requests: list[int] = []
    connections = 0

    async def exercise() -> None:
        async def origin(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            nonlocal connections
            connections += 1
            number = connections
            try:
                while True:
                    try:
                        _ = await reader.readuntil(b"\r\n\r\n")
                    except asyncio.IncompleteReadError as error:
                        assert not error.partial
                        return
                    requests.append(number)
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    await writer.drain()
            finally:
                await close_writer(writer)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server = await asyncio.start_server(
            origin, "127.0.0.1", origin_port, ssl=context
        )
        async with server:
            with managed_processes() as start:
                node = ForwardNode(port=entry, ca=ca, certificate=certificate, key=key)
                process = start(write_forward_node(tmp_path / "entry", node))
                assert wait_for_proxy("127.0.0.1", entry, timeout=3, proc=process)
                target = f"127.0.0.1:{origin_port}/"
                assert (await _exchange(entry, f"https://{target}", "GET", b""))[
                    0
                ] == 200
                # A plain HTTP request to the same authority must not borrow
                # the established TLS connection and silently become HTTPS.
                assert (await _exchange(entry, f"http://{target}", "GET", b""))[
                    0
                ] == 502
                assert (await _exchange(entry, f"https://{target}", "GET", b""))[
                    0
                ] == 200
                assert requests == [1, 1]
                assert connections == 1

    asyncio.run(exercise())


async def _chunk(reader: asyncio.StreamReader) -> bytes | None:
    size = int((await reader.readline()).split(b";", 1)[0], 16)
    if size == 0:
        assert await reader.readline() == b"\r\n"
        return None
    data = await reader.readexactly(size)
    assert await reader.readexactly(2) == b"\r\n"
    return data


@pytest.mark.parametrize("listener", ["http", "https", "http3"])
def test_https_forward_streams_before_upload_eof_across_h3_proxy(
    tmp_path: Path, listener: ProxyKind
) -> None:
    certificate, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["127.0.0.1", "proxy.test"]
    )
    origin_port, relay, entry = get_unique_port(), get_unique_port(), get_unique_port()
    payload = bytes(range(256)) * 1024
    completed = asyncio.Event()

    async def exercise() -> None:
        async def origin(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                headers = await reader.readuntil(b"\r\n\r\n")
                assert headers.startswith(b"POST / HTTP/1.1\r\n")
                first = await _chunk(reader)
                assert first == b"first"
                writer.write(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    + b"5\r\nfirst\r\n"
                )
                await writer.drain()
                body = b""
                while (data := await _chunk(reader)) is not None:
                    body += data
                assert body == payload
                writer.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
                await writer.drain()
                completed.set()
            finally:
                await close_writer(writer)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        async with asyncio.TaskGroup() as peers:

            def connected(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                _ = peers.create_task(origin(reader, writer))

            server = await asyncio.start_server(
                connected, "127.0.0.1", origin_port, ssl=context
            )
            async with server:
                with managed_processes() as start:
                    for name, node in [
                        (
                            "relay",
                            ForwardNode(
                                port=relay,
                                listener="http3",
                                ca=ca,
                                certificate=certificate,
                                key=key,
                            ),
                        ),
                        (
                            "entry",
                            ForwardNode(
                                port=entry,
                                listener=listener,
                                ca=ca,
                                certificate=certificate,
                                key=key,
                                upstream_port=relay,
                                upstream_kind="http3",
                            ),
                        ),
                    ]:
                        process = start(write_forward_node(tmp_path / name, node))
                        wait = (
                            wait_for_udp_port_bound
                            if node.listener == "http3"
                            else wait_for_proxy
                        )
                        assert wait("127.0.0.1", node.port, timeout=3, proc=process)
                    authority = f"127.0.0.1:{origin_port}"
                    if listener == "http3":
                        configuration = QuicConfiguration(
                            is_client=True, alpn_protocols=["h3"]
                        )
                        configuration.server_name = "proxy.test"
                        configuration.load_verify_locations(ca)
                        async with connect(
                            "127.0.0.1",
                            entry,
                            configuration=configuration,
                            create_protocol=LifecycleClient,
                        ) as client:
                            assert isinstance(client, LifecycleClient)
                            stream = client.request(
                                b"POST", authority=authority.encode()
                            )
                            client.http.send_data(stream, b"first", end_stream=False)
                            client.transmit()
                            await client.read_data(stream, b"first")
                            client.http.send_data(stream, payload, end_stream=True)
                            client.transmit()
                            await client.read_data(stream, payload)
                            assert await client.read_end(stream) == []
                    else:
                        tls: ssl.SSLContext | None = None
                        if listener == "https":
                            tls = ssl.create_default_context(cafile=ca)
                        reader, writer = await asyncio.open_connection(
                            "127.0.0.1",
                            entry,
                            ssl=tls,
                            server_hostname="proxy.test" if tls is not None else None,
                        )
                        try:
                            writer.write(
                                f"POST https://{authority}/ HTTP/1.1\r\n".encode()
                                + f"Host: {authority}\r\n".encode()
                                + b"Transfer-Encoding: chunked\r\n"
                                + b"Connection: close\r\n\r\n5\r\nfirst\r\n"
                            )
                            await writer.drain()
                            headers = await reader.readuntil(b"\r\n\r\n")
                            assert headers.startswith(b"HTTP/1.1 200 ")
                            assert await _chunk(reader) == b"first"
                            writer.write(
                                f"{len(payload):x}\r\n".encode()
                                + payload
                                + b"\r\n0\r\n\r\n"
                            )
                            await writer.drain()
                            received = b""
                            while (data := await _chunk(reader)) is not None:
                                received += data
                            assert received == payload
                        finally:
                            await close_writer(writer)
                    assert completed.is_set()

    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["untrusted", "wrong-host", "timeout"])
def test_direct_https_forward_reports_tls_failures(
    tmp_path: Path, failure: Literal["untrusted", "wrong-host", "timeout"]
) -> None:
    certificate, key, ca, ca_key = generate_test_certificates(
        str(tmp_path), san_entries=["127.0.0.1"]
    )
    if failure == "wrong-host":
        certificate, key = generate_server_cert(
            str(tmp_path), ca, ca_key, ["wrong.test"], cert_name="wrong-host"
        )
    origin_port, entry = get_unique_port(), get_unique_port()

    async def exercise() -> None:
        async def peer(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                _ = await reader.read()
            finally:
                await close_writer(writer)

        context: ssl.SSLContext | None = None
        if failure != "timeout":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
        server = await asyncio.start_server(peer, "127.0.0.1", origin_port, ssl=context)
        async with server:
            node = ForwardNode(
                port=entry,
                ca=None if failure == "untrusted" else ca,
                certificate=certificate,
                key=key,
                handshake_timeout="100ms",
            )
            with managed_processes() as start:
                process = start(write_forward_node(tmp_path / "entry", node))
                assert wait_for_proxy("127.0.0.1", entry, timeout=3, proc=process)
                status, headers, _ = await _exchange(
                    entry, f"https://127.0.0.1:{origin_port}/", "GET", b""
                )
                assert status == (504 if failure == "timeout" else 502)
                expected = (
                    b"connection_timeout"
                    if failure == "timeout"
                    else b"tls_certificate_error"
                )
                assert expected in headers

    asyncio.run(exercise())
