"""Listener upgrade preserves bytes sent together with CONNECT headers."""

import socket
import ssl
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import TargetServerFactory


@pytest.mark.parametrize("protocol", ["http", "https"])
def test_connect_upgrade_preserves_preread_and_subsequent_bytes(
    tmp_path: Path,
    target_server: TargetServerFactory,
    protocol: Literal["http", "https"],
) -> None:
    payload = b"early-tunnel-data\x00\xff\r\n\r\n"
    followup = b"later-tunnel-data"

    def echo(connection: socket.socket) -> None:
        with connection:
            connection.settimeout(5)
            remaining = len(payload) + len(followup)
            while remaining:
                data = connection.recv(remaining)
                assert data
                connection.sendall(data)
                remaining -= len(data)

    target = get_unique_port()
    _ = target_server(target, echo)
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    server: ConfigDict = {
        "name": "entry",
        "listeners": ["entry"],
        "service": "direct",
    }
    if protocol == "https":
        server["certificates"] = [{"cert_path": cert, "key_path": key}]
    config: ConfigDict = {
        "plugins": {"upstream": {"upstreams": [{"name": "direct"}]}},
        "listeners": [{"name": "entry", "kind": protocol}],
        "services": [
            {"name": "direct", "kind": "upstream.upstream", "upstream": "direct"}
        ],
        "servers": [server],
    }
    with running_proxy(tmp_path, config) as proxy:
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        stream = (
            ssl.create_default_context(cafile=ca).wrap_socket(
                raw, server_hostname="localhost"
            )
            if protocol == "https"
            else raw
        )
        with stream:
            authority = f"127.0.0.1:{target}"
            headers = (
                f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            ).encode()
            stream.sendall(headers + payload)
            with stream.makefile("rb") as reader:
                assert reader.readline().split()[1] == b"200"
                while True:
                    line = reader.readline()
                    assert line
                    if line == b"\r\n":
                        break
                assert reader.read(len(payload)) == payload
                stream.sendall(followup)
                assert reader.read(len(followup)) == followup
