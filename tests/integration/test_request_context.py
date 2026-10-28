"""Request identity crosses proxy hops and terminal tunnel logs retain its ID."""

import socket
import time
from http.client import HTTPConnection
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel

from tests.fixtures.access_log_configuration import enable_access_log
from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import JsonValue
from tests.fixtures.forward_scenario import ForwardNode, ProxyKind, write_forward_node
from tests.fixtures.http_echo import http_echo_handler
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import managed_processes
from tests.fixtures.tcp_peer import TargetServerFactory, one_shot_echo_handler


class AccessEntry(BaseModel):
    status: int
    extensions: dict[str, JsonValue]


def entries(directory: Path) -> list[AccessEntry]:
    result: list[AccessEntry] = []
    for path in (directory / "logs").glob("access*"):
        text = path.read_text()
        if text and not text.endswith("\n"):
            return []
        result.extend(
            AccessEntry.model_validate_json(line) for line in text.splitlines()
        )
    return result


def diagnostics(directory: Path) -> str:
    return "".join(
        path.read_text() for path in (directory / "logs").glob("neoproxy.log*")
    )


@pytest.mark.parametrize("upstream_kind", ["http", "https", "http3"])
@pytest.mark.parametrize("incoming", [None, "opaque-client-id"])
@pytest.mark.parametrize("mode", ["forward", "tunnel"])
def test_request_id_propagates_and_tunnel_logs_only_after_transfer(
    tmp_path: Path,
    target_server: TargetServerFactory,
    upstream_kind: ProxyKind,
    incoming: str | None,
    mode: Literal["forward", "tunnel"],
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["127.0.0.1", "proxy.test"]
    )
    origin_port, upstream_port, entry_port = (
        get_unique_port(),
        get_unique_port(),
        get_unique_port(),
    )
    _ = target_server(
        origin_port, http_echo_handler if mode == "forward" else one_shot_echo_handler
    )
    upstream_dir, entry_dir = tmp_path / "upstream", tmp_path / "entry"
    upstream_config = write_forward_node(
        upstream_dir,
        ForwardNode(
            port=upstream_port, listener=upstream_kind, certificate=cert, key=key
        ),
    )
    entry_config = write_forward_node(
        entry_dir,
        ForwardNode(
            port=entry_port,
            certificate=cert,
            key=key,
            ca=ca,
            upstream_port=upstream_port,
            upstream_kind=upstream_kind,
            h3_max_connections=1,
        ),
    )
    fields = [
        "request.id",
        "upstream.protocol",
        "upstream.connection.peer",
        "upstream.connection.reused",
        "upstream.dns.host",
        "upstream.dns.duration_ms",
        "upstream.dns.addresses",
        "upstream.tcp.connect_ms",
        "upstream.tls.handshake_ms",
    ]
    enable_access_log(upstream_config, fields)
    enable_access_log(entry_config, fields)
    with managed_processes() as start:
        upstream = start(upstream_config)
        assert upstream.wait_ready()
        entry = start(entry_config)
        assert entry.wait_ready()
        with socket.create_connection(("127.0.0.1", entry_port), timeout=5) as client:
            target = f"127.0.0.1:{origin_port}"
            line = f"CONNECT {target}" if mode == "tunnel" else f"POST http://{target}/"
            headers = f"{line} HTTP/1.1\r\nHost: {target}\r\n"
            if incoming is not None:
                headers += f"X-Request-ID: {incoming}\r\n"
            if mode == "forward":
                headers += "Connection: close\r\nContent-Length: 4\r\n"
            client.sendall(
                headers.encode() + b"\r\n" + (b"ping" if mode == "forward" else b"")
            )
            with client.makefile("rb") as response:
                assert response.readline().startswith(b"HTTP/1.1 200 ")
                received: dict[bytes, bytes] = {}
                id_count = 0
                while (header := response.readline()) != b"\r\n":
                    assert header
                    name, separator, value = header.partition(b":")
                    assert separator
                    received[name.lower()] = value.strip()
                    if name.lower() == b"x-request-id":
                        id_count += 1
                request_id = received[b"x-request-id"].decode()
                assert id_count == 1
                if incoming is not None:
                    assert request_id == incoming
                else:
                    assert len(request_id) == 32
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not (
                    entries(entry_dir) and entries(upstream_dir)
                ):
                    time.sleep(0.01)
                for directory in (entry_dir, upstream_dir):
                    access = entries(directory)
                    assert len(access) == 1
                    assert access[0].extensions["request.id"] == request_id
                    assert isinstance(
                        access[0].extensions["upstream.connection.reused"], bool
                    )
                    assert "tunnel_finished" not in diagnostics(directory)
                assert (
                    entries(entry_dir)[0].extensions["upstream.protocol"]
                    == upstream_kind
                )
                if mode == "forward":
                    assert (
                        entries(upstream_dir)[0].extensions["upstream.protocol"]
                        == "http"
                    )
                else:
                    assert (
                        "upstream.protocol" not in entries(upstream_dir)[0].extensions
                    )
                if mode == "tunnel":
                    client.sendall(b"ping")
                    assert response.read(9) == b"ECHO:ping"
                    client.shutdown(socket.SHUT_WR)
                    assert response.read() == b""
                else:
                    assert response.read() == b"ping"
            if mode == "tunnel":
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not all(
                    "tunnel_finished" in diagnostics(directory)
                    for directory in (entry_dir, upstream_dir)
                ):
                    time.sleep(0.01)
                for directory in (entry_dir, upstream_dir):
                    terminal = [
                        line
                        for line in diagnostics(directory).splitlines()
                        if "tunnel_finished" in line
                    ]
                    assert len(terminal) == 1
                    assert f"request_id={request_id}" in terminal[0]
                    assert "bytes_client_to_upstream=4" in terminal[0]
                    assert "bytes_upstream_to_client=9" in terminal[0]
                    assert "end_reason=completed" in terminal[0]
        for directory in (entry_dir, upstream_dir):
            assert "origin_dns" not in diagnostics(directory)
            assert "origin_connect" not in diagnostics(directory)
        if mode == "forward":
            second = HTTPConnection("127.0.0.1", entry_port, timeout=5)
            try:
                second.request(
                    "POST",
                    f"http://127.0.0.1:{origin_port}/",
                    body=b"next",
                    headers={"X-Request-ID": "second-id"},
                )
                response = second.getresponse()
                assert response.status == 200
                assert response.getheader("X-Request-ID") == "second-id"
                assert response.read() == b"next"
            finally:
                second.close()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and len(entries(entry_dir)) != 2:
                time.sleep(0.01)
            reused = entries(entry_dir)[1]
            assert reused.extensions["request.id"] == "second-id"
            assert reused.extensions["upstream.protocol"] == upstream_kind
            assert reused.extensions["upstream.connection.reused"] is True
            assert "upstream.tcp.connect_ms" not in reused.extensions
            assert "upstream.tls.handshake_ms" not in reused.extensions


def test_dns_failure_records_native_access_fields_and_response_id(
    tmp_path: Path,
) -> None:
    port = get_unique_port()
    config = write_forward_node(
        tmp_path, ForwardNode(port=port, certificate="", key="")
    )
    enable_access_log(
        config,
        [
            "request.id",
            "upstream.protocol",
            "upstream.dns.host",
            "upstream.dns.duration_ms",
            "upstream.error.phase",
            "upstream.error.kind",
        ],
    )
    with managed_processes() as start:
        process = start(config)
        assert process.wait_ready()
        client = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            client.request(
                "GET", "http://bad..name/", headers={"X-Request-ID": "dns-error-id"}
            )
            response = client.getresponse()
            assert response.status == 502
            assert response.getheader("X-Request-ID") == "dns-error-id"
            _ = response.read()
        finally:
            client.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not entries(tmp_path):
            time.sleep(0.01)
        entry = entries(tmp_path)[0]
        assert entry.extensions["request.id"] == "dns-error-id"
        assert entry.extensions["upstream.protocol"] == "http"
        assert entry.extensions["upstream.error.phase"] == "dns"
        assert entry.extensions["upstream.error.kind"] == "dns_error"
        assert entry.extensions["upstream.dns.host"] == "bad..name"
        assert isinstance(entry.extensions["upstream.dns.duration_ms"], int)
        assert "origin_dns" not in diagnostics(tmp_path)
