"""SOCKS5 method selection follows the configured service authentication policy."""

import socket
from pathlib import Path

import pytest

from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.socks5_client import socks5_connect_ipv4
from tests.fixtures.socks5_configuration import create_socks5_config
from tests.fixtures.socks5_protocol import ReplyCode
from tests.fixtures.socks5_result import CommandReply


def _receive_exact(client: socket.socket, size: int) -> bytes:
    received = b""
    while len(received) < size:
        chunk = client.recv(size - len(received))
        assert chunk, "connection closed before the expected reply"
        received += chunk
    return received


@pytest.mark.parametrize(
    "methods",
    [
        pytest.param(b"\x00", id="no-auth-only"),
        pytest.param(b"\x02", id="password-only"),
        pytest.param(b"\x00\x02", id="tsocks"),
        pytest.param(b"\x02\x00", id="password-first"),
        pytest.param(b"\x01", id="unsupported"),
    ],
)
@pytest.mark.parametrize(
    "password",
    [
        pytest.param(None, id="no-auth-configured"),
        pytest.param(b"correct", id="valid-credentials"),
        pytest.param(b"wrong", id="invalid-credentials"),
    ],
)
def test_socks5_selects_only_the_configured_authentication_method(
    tmp_path: Path, methods: bytes, password: bytes | None
) -> None:
    proxy_port = get_unique_port()
    target_port = get_unique_port()
    config = create_socks5_config(
        proxy_port,
        str(tmp_path),
        auth_type="password" if password is not None else None,
        users=[{"username": "user", "password": "correct"}],
    )
    required_method = 0x02 if password is not None else 0x00
    accepted = required_method in methods
    authorized = accepted and password in (None, b"correct")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
        target.bind(("127.0.0.1", target_port))
        target.listen(1)
        target.settimeout(2)
        process = start_proxy(config)
        try:
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=3, proc=process)
            with socket.create_connection(
                ("127.0.0.1", proxy_port), timeout=2
            ) as client:
                # Classic tsocks always offers both 00 and 02, even without a
                # configured password. The server must select its configured mode.
                client.sendall(bytes([5, len(methods)]) + methods)
                assert _receive_exact(client, 2) == bytes(
                    [5, required_method if accepted else 0xFF]
                )
                if accepted and password is not None:
                    client.sendall(b"\x01\x04user" + bytes([len(password)]) + password)
                    reply = _receive_exact(client, 2)
                    assert reply[0] == 1
                    assert (reply[1] == 0) is authorized

                if authorized:
                    reply = socks5_connect_ipv4(client, "127.0.0.1", target_port)
                    assert isinstance(reply, CommandReply)
                    assert reply.code is ReplyCode.SUCCESS
                    origin = target.accept()[0]
                    with origin:
                        origin.settimeout(2)
                        client.sendall(b"upload")
                        assert _receive_exact(origin, 6) == b"upload"
                        origin.sendall(b"response")
                        assert _receive_exact(client, 8) == b"response"
                else:
                    assert client.recv(1) == b"", "rejected handshake remained open"
        finally:
            terminate_process(process)
        assert process.returncode == 0
        target.setblocking(False)
        try:
            unexpected = target.accept()[0]
        except BlockingIOError:
            pass
        else:
            unexpected.close()
            pytest.fail("unauthorized or duplicate target connection")
