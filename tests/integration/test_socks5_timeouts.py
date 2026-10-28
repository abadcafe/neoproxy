"""SOCKS5 negotiation, credentials and command share one header deadline."""

import socket
import time
from pathlib import Path

import pytest

from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.socks5_configuration import create_socks5_config


@pytest.mark.parametrize("phase", ["negotiation", "authentication", "command"])
def test_socks5_header_deadline_bounds_partial_frames(
    tmp_path: Path, phase: str
) -> None:
    port = get_unique_port()
    config = create_socks5_config(port, str(tmp_path), header_read_timeout="500ms")
    process = start_proxy(config)
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            start = time.monotonic()
            if phase != "negotiation":
                client.sendall(bytes([5, 1, 2]))
                assert client.recv(2, socket.MSG_WAITALL) == bytes([5, 2])
            if phase == "command":
                client.sendall(bytes([1, 1, ord("u"), 1, ord("p")]))
                assert client.recv(2, socket.MSG_WAITALL) == bytes([1, 0])
            client.sendall(bytes([5 if phase != "authentication" else 1]))
            assert client.recv(1) == b""
            assert 0.3 <= time.monotonic() - start < 2
        assert process.poll() is None
    finally:
        terminate_process(process)


@pytest.mark.parametrize("complete_command", [False, True])
def test_socks5_phases_share_accept_deadline(
    tmp_path: Path, complete_command: bool
) -> None:
    port = get_unique_port()
    config = create_socks5_config(
        port,
        str(tmp_path),
        header_read_timeout="2s",
        auth_type="password",
        users=[{"username": "user", "password": "secret"}],
    )
    process = start_proxy(config)
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
            start = time.monotonic()
            time.sleep(0.6)
            client.sendall(bytes([5, 1, 2]))
            assert client.recv(2, socket.MSG_WAITALL) == bytes([5, 2])
            time.sleep(0.6)
            client.sendall(bytes([1, 1, ord("u"), 1, ord("p")]))
            assert client.recv(2, socket.MSG_WAITALL) == bytes([1, 0])
            if complete_command:
                client.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1, 0, 80]))
                # Wrong credentials reach shared auth only after a full command.
                assert client.recv(10, socket.MSG_WAITALL) == bytes(
                    [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]
                )
            else:
                client.sendall(bytes([5]))
                assert client.recv(1) == b""
                # Neither completed phase nor partial command resets the budget.
                assert 1.7 <= time.monotonic() - start < 2.8
    finally:
        terminate_process(process)
