"""SOCKS5 handshake and CONNECT command deadlines are independent."""

import socket
import time
from pathlib import Path

import pytest

from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.socks5_configuration import create_socks5_config


@pytest.mark.parametrize("command_phase", [False, True])
def test_socks5_each_phase_uses_its_own_deadline(
    tmp_path: Path, command_phase: bool
) -> None:
    port = get_unique_port()
    config = create_socks5_config(
        port,
        str(tmp_path),
        handshake_timeout="2s" if command_phase else "200ms",
        connect_timeout="200ms" if command_phase else "2s",
    )
    process = start_proxy(config)
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", port), timeout=1.5) as client:
            if command_phase:
                client.sendall(bytes([5, 1, 0]))
                assert client.recv(2, socket.MSG_WAITALL) == bytes([5, 0])
            start = time.monotonic()
            # A partial frame must still be bounded by the phase deadline.
            client.sendall(bytes([5]))
            assert client.recv(1) == b""
            assert 0.1 <= time.monotonic() - start < 1.5
        assert process.poll() is None
    finally:
        terminate_process(process)


def test_socks5_connect_deadline_starts_after_handshake(tmp_path: Path) -> None:
    port = get_unique_port()
    config = create_socks5_config(
        port,
        str(tmp_path),
        auth_type="password",
        users=[{"username": "user", "password": "secret"}],
        handshake_timeout="2s",
        connect_timeout="1s",
    )
    process = start_proxy(config)
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            # The command budget is fresh after the handshake, not at accept.
            time.sleep(1.2)
            client.sendall(bytes([5, 1, 0]))
            assert client.recv(2, socket.MSG_WAITALL) == bytes([5, 0])
            time.sleep(0.2)
            client.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1, 0, 80]))
            # Shared auth handles the fully decoded CONNECT, without origin I/O.
            assert client.recv(10, socket.MSG_WAITALL) == bytes(
                [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]
            )
    finally:
        terminate_process(process)


def test_socks5_connect_can_outlive_handshake_timeout(tmp_path: Path) -> None:
    port = get_unique_port()
    config = create_socks5_config(
        port,
        str(tmp_path),
        handshake_timeout="200ms",
        connect_timeout="2s",
    )
    process = start_proxy(config)
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(bytes([5, 1, 0]))
            assert client.recv(2, socket.MSG_WAITALL) == bytes([5, 0])
            time.sleep(0.4)
            # BIND is rejected by command decoding; reaching that reply proves
            # the shorter handshake timer did not expire the command phase.
            client.sendall(bytes([5, 2, 0, 1, 127, 0, 0, 1, 0, 80]))
            reply = client.recv(10, socket.MSG_WAITALL)
            assert reply[:2] == bytes([5, 7])
    finally:
        terminate_process(process)
