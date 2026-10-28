"""HTTP/HTTPS listener keep-alive configuration, observed on the wire."""

import http.client
import socket
import ssl
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http_scenario import running_proxy


@pytest.mark.parametrize("protocol", ["http", "https"])
@pytest.mark.parametrize("keep_alive", [None, True, False])
def test_listener_keep_alive_controls_connection_reuse(
    tmp_path: Path, protocol: Literal["http", "https"], keep_alive: bool | None
) -> None:
    listener: ConfigDict = {"name": "entry", "kind": protocol}
    if keep_alive is not None:
        listener["keep_alive"] = keep_alive
    server: ConfigDict = {"name": "entry", "listeners": ["entry"], "service": "echo"}
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    if protocol == "https":
        server["certificates"] = [{"cert_path": cert, "key_path": key}]
    config: ConfigDict = {
        "plugins": {"echo": {}},
        "listeners": [listener],
        "services": [{"name": "echo", "kind": "echo.echo"}],
        "servers": [server],
    }
    with running_proxy(tmp_path, config) as proxy:
        raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=3)
        stream = (
            ssl.create_default_context(cafile=ca).wrap_socket(
                raw, server_hostname="localhost"
            )
            if protocol == "https"
            else raw
        )
        with stream:
            for path in ["/first", "/second"]:
                stream.sendall(
                    f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
                )
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 200
                _ = response.read()
                if keep_alive is False:
                    assert response.getheader("Connection", "").lower() == "close"
                    response.close()
                    assert stream.recv(1) == b""
                    break
                assert not response.will_close
                response.close()
