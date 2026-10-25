"""Public lifecycle behavior of managed TCP target servers."""

import socket

import pytest

from tests.fixtures.ports import get_unique_port
from tests.fixtures.tcp_peer import (
    echo_handler,
    managed_target_servers,
    send_ok_and_close,
)


def test_managed_target_servers_exchange_data_and_close_all_listeners() -> None:
    with managed_target_servers() as start:
        listeners: list[socket.socket] = []
        for _ in range(2):
            port = get_unique_port()
            listener = start(port, echo_handler)
            listeners.append(listener)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(b"hello")
                assert client.recv(1024) == b"ECHO:hello"
    assert all(listener.fileno() == -1 for listener in listeners)


def test_send_ok_and_close_delivers_complete_message_after_short_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_send = socket.socket.send

    def short_send(connection: socket.socket, data: bytes, flags: int = 0) -> int:
        return original_send(connection, data[:1], flags)

    # A single TCP send is allowed to accept only a prefix. Exercise
    # the public helper over real sockets with that boundary behavior.
    monkeypatch.setattr(socket.socket, "send", short_send)
    sender, receiver = socket.socketpair()
    with sender, receiver:
        send_ok_and_close(sender)
        assert receiver.recv(16) == b"OK"
        assert receiver.recv(16) == b""
