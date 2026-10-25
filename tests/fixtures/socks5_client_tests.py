"""Public SOCKS5 client contracts over real stream sockets."""

import socket
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import partial

import pytest

from tests.fixtures.socks5_client import (
    socks5_connect_domain,
    socks5_connect_ipv4,
    socks5_connect_ipv6,
    socks5_handshake_no_auth,
    socks5_handshake_password,
    socks5_request_unsupported_method,
    socks5_send_bind_command,
    socks5_send_udp_associate,
)
from tests.fixtures.socks5_protocol import (
    AddressType,
    AuthMethod,
    AuthStatus,
    ReplyCode,
)
from tests.fixtures.socks5_result import (
    AuthenticationResult,
    AuthReply,
    CommandReply,
    CommandResult,
    ErrorKind,
    MethodReply,
    SocksError,
)

type ServerScript = Callable[[socket.socket], None]
type CommandCall = Callable[[socket.socket], CommandResult]


def receive(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        assert chunk, f"client stopped after {len(data)}/{size} bytes"
        data += chunk
    return data


@contextmanager
def peer(script: ServerScript) -> Generator[socket.socket, None, None]:
    client, server = socket.socketpair()
    with client, server, ThreadPoolExecutor(max_workers=1) as executor:
        client.settimeout(1)
        server.settimeout(1)
        completed = executor.submit(script, server)
        try:
            yield client
        finally:
            client.close()
            # Peer assertions must fail the test, not disappear in a thread.
            completed.result(timeout=2)


@pytest.fixture
def fragmented_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    original_recv = socket.socket.recv

    def one_byte(sock: socket.socket, size: int, flags: int = 0) -> bytes:
        return original_recv(sock, min(size, 1), flags)

    monkeypatch.setattr(socket.socket, "recv", one_byte)


@pytest.mark.parametrize("method", [AuthMethod.NONE, AuthMethod.NO_ACCEPTABLE])
@pytest.mark.usefixtures("fragmented_reads")
def test_handshake_returns_method_reply_with_fragmented_response(
    method: AuthMethod,
) -> None:
    def server(sock: socket.socket) -> None:
        assert receive(sock, 3) == b"\x05\x01\x00"
        sock.sendall(bytes([5, method.value]))

    with peer(server) as client:
        assert socks5_handshake_no_auth(client) == MethodReply(method)


@pytest.mark.parametrize("status", [0, 1, 255])
@pytest.mark.usefixtures("fragmented_reads")
def test_password_returns_auth_reply_for_all_status_bytes(
    status: int,
) -> None:
    def server(sock: socket.socket) -> None:
        assert receive(sock, 3) == b"\x05\x01\x02"
        sock.sendall(b"\x05\x02")
        assert receive(sock, 11) == b"\x01\x04user\x04pass"
        sock.sendall(bytes([1, status]))

    with peer(server) as client:
        expected = AuthStatus.SUCCESS if status == 0 else AuthStatus.FAILURE
        assert socks5_handshake_password(client, "user", "pass") == AuthReply(expected)


def test_password_method_refusal_is_distinct_from_authentication_reply() -> None:
    def server(sock: socket.socket) -> None:
        assert receive(sock, 3) == b"\x05\x01\x02"
        sock.sendall(b"\x05\xff")
        assert sock.recv(1) == b"", "credentials sent after method refusal"

    with peer(server) as client:
        assert socks5_handshake_password(client, "user", "pass") == MethodReply(
            AuthMethod.NO_ACCEPTABLE
        )


def test_unsupported_method_has_a_typed_selection_reply() -> None:
    def server(sock: socket.socket) -> None:
        assert receive(sock, 3) == b"\x05\x01\x01"
        sock.sendall(b"\x05\xff")

    with peer(server) as client:
        assert socks5_request_unsupported_method(client) == MethodReply(
            AuthMethod.NO_ACCEPTABLE
        )


@pytest.mark.parametrize(
    ("command", "wire_request"),
    [
        (
            partial(socks5_connect_ipv4, target_ip="127.0.0.1", target_port=443),
            b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb",
        ),
        (
            partial(socks5_connect_ipv6, target_ip="::1", target_port=443),
            b"\x05\x01\x00\x04" + b"\x00" * 15 + b"\x01\x01\xbb",
        ),
        (
            partial(socks5_connect_domain, domain="test", target_port=443),
            b"\x05\x01\x00\x03\x04test\x01\xbb",
        ),
        (socks5_send_bind_command, b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x00"),
        (socks5_send_udp_associate, b"\x05\x03\x00\x01" + b"\x00" * 6),
    ],
)
@pytest.mark.usefixtures("fragmented_reads")
def test_command_interfaces_return_typed_replies(
    command: CommandCall, wire_request: bytes
) -> None:
    def server(sock: socket.socket) -> None:
        assert receive(sock, len(wire_request)) == wire_request
        sock.sendall(b"\x05\x07\x00\x01\x7f\x00\x00\x01\x1f\x90")

    with peer(server) as client:
        result = command(client)
        assert result == CommandReply(
            ReplyCode.COMMAND_NOT_SUPPORTED, AddressType.IPV4, b"\x7f\x00\x00\x01", 8080
        )


@pytest.mark.parametrize(
    ("kind", "address", "encoded"),
    [
        (AddressType.IPV4, b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x01"),
        (AddressType.IPV6, b"\x00" * 15 + b"\x01", b"\x00" * 15 + b"\x01"),
        (AddressType.DOMAIN, b"bound.test", b"\x0abound.test"),
    ],
)
@pytest.mark.usefixtures("fragmented_reads")
def test_command_consumes_full_bind_address_without_eating_tunnel_data(
    kind: AddressType, address: bytes, encoded: bytes
) -> None:
    def server(sock: socket.socket) -> None:
        assert receive(sock, 10) == b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"
        sock.sendall(bytes([5, 0, 0, kind.value]) + encoded + b"\x01\xbbTUNNEL")

    with peer(server) as client:
        result = socks5_connect_ipv4(client, "127.0.0.1", 80)
        assert result == CommandReply(ReplyCode.SUCCESS, kind, address, 443)
        assert receive(client, 6) == b"TUNNEL"


@pytest.mark.parametrize(
    "reply",
    [b"", b"\x05", b"\x05\x00", b"\x05\x00\x00\x01\x7f", b"\x05\x00\x00\x03\x04xy"],
)
def test_command_truncation_returns_read_error(reply: bytes) -> None:
    def server(sock: socket.socket) -> None:
        _ = receive(sock, 10)
        sock.sendall(reply)
        sock.shutdown(socket.SHUT_WR)

    with peer(server) as client:
        result = socks5_connect_ipv4(client, "127.0.0.1", 80)
        assert isinstance(result, SocksError)
        assert result.kind is ErrorKind.EOF


@pytest.mark.parametrize(
    ("reply", "kind"),
    [
        (b"\x04\x00\x00\x01", ErrorKind.INVALID_VERSION),
        (b"\x05\x00\x01\x01", ErrorKind.INVALID_RESERVED),
        (b"\x05\x99\x00\x01", ErrorKind.UNSUPPORTED_CODE),
        (b"\x05\x00\x00\x99", ErrorKind.UNSUPPORTED_CODE),
    ],
)
def test_command_malformed_reply_returns_typed_error(
    reply: bytes, kind: ErrorKind
) -> None:
    def server(sock: socket.socket) -> None:
        _ = receive(sock, 10)
        sock.sendall(reply)

    with peer(server) as client:
        result = socks5_connect_ipv4(client, "127.0.0.1", 80)
        assert isinstance(result, SocksError)
        assert result.kind is kind


@pytest.mark.parametrize("reply", [b"\x04\x00", b"\x05\x99"])
def test_method_selection_errors_do_not_become_auth_status(reply: bytes) -> None:
    def server(sock: socket.socket) -> None:
        _ = receive(sock, 3)
        sock.sendall(reply)

    with peer(server) as client:
        result = socks5_handshake_password(client, "user", "pass")
        assert isinstance(result, SocksError)


def test_closed_socket_returns_io_error() -> None:
    with socket.socket() as client:
        client.close()
        result = socks5_handshake_no_auth(client)
        assert isinstance(result, SocksError)
        assert result.kind is ErrorKind.IO


def test_password_subnegotiation_version_returns_protocol_error() -> None:
    def server(sock: socket.socket) -> None:
        _ = receive(sock, 3)
        sock.sendall(b"\x05\x02")
        assert receive(sock, 11) == b"\x01\x04user\x04pass"
        sock.sendall(b"\x05\x00")

    with peer(server) as client:
        result = socks5_handshake_password(client, "user", "pass")
        assert isinstance(result, SocksError)
        assert result.kind is ErrorKind.INVALID_VERSION


@pytest.mark.parametrize(
    "exchange",
    [
        partial(socks5_connect_domain, domain="x" * 256, target_port=80),
        partial(socks5_connect_ipv4, target_ip="not an IPv4 address", target_port=80),
        partial(socks5_connect_ipv6, target_ip="not an IPv6 address", target_port=80),
        partial(socks5_connect_ipv4, target_ip="127.0.0.1", target_port=65536),
        partial(socks5_handshake_password, username="é" * 128, password="p"),
    ],
)
def test_unencodable_input_returns_error_without_sending_a_partial_frame(
    exchange: Callable[[socket.socket], AuthenticationResult | CommandResult],
) -> None:
    def server(sock: socket.socket) -> None:
        assert sock.recv(1) == b""

    with peer(server) as client:
        result = exchange(client)
        assert isinstance(result, SocksError)
        assert result.kind is ErrorKind.INVALID_INPUT


def test_read_timeout_returns_io_error() -> None:
    def server(sock: socket.socket) -> None:
        assert receive(sock, 3) == b"\x05\x01\x00"
        assert sock.recv(1) == b""

    with peer(server) as client:
        client.settimeout(0.01)
        result = socks5_handshake_no_auth(client)
        assert isinstance(result, SocksError)
        assert result.kind is ErrorKind.IO
