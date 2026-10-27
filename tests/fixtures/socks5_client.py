"""module: socks5_client; responsibility: execute typed SOCKS5 exchanges.
Public operations: socks5_handshake_no_auth, socks5_handshake_password,
socks5_connect_ipv4, socks5_connect_ipv6, socks5_connect_domain,
socks5_send_bind_command, socks5_send_udp_associate,
socks5_request_unsupported_method.
Data entities: none.
Tests: socks5_client_tests.py and SOCKS5 integration consumers.
"""

import ipaddress
import socket

from .socks5_protocol import (
    VERSION,
    AddressType,
    AuthMethod,
    AuthStatus,
    Command,
    ReplyCode,
    decode_wire,
)
from .socks5_result import (
    AuthenticationResult,
    AuthReply,
    CommandReply,
    CommandResult,
    ErrorKind,
    MethodReply,
    SocksError,
)


def _send(sock: socket.socket, data: bytes) -> SocksError | None:
    try:
        sock.sendall(data)
    except OSError as error:
        return SocksError(ErrorKind.IO, str(error))
    return None


def _read_exact(sock: socket.socket, size: int) -> bytes | SocksError:
    data = bytearray()
    while len(data) < size:
        try:
            chunk = sock.recv(size - len(data))
        except OSError as error:
            return SocksError(ErrorKind.IO, str(error))
        if not chunk:
            return SocksError(
                ErrorKind.EOF, f"expected {size} bytes, received {len(data)}"
            )
        data.extend(chunk)
    return bytes(data)


def _select_method(
    sock: socket.socket, offered: AuthMethod
) -> MethodReply | SocksError:
    error = _send(sock, bytes([VERSION, 1, offered.value]))
    if error is not None:
        return error
    response = _read_exact(sock, 2)
    if isinstance(response, SocksError):
        return response
    if response[0] != VERSION:
        return SocksError(
            ErrorKind.INVALID_VERSION, f"method reply version {response[0]}"
        )
    method = decode_wire(AuthMethod, response[1])
    if method is None:
        return SocksError(
            ErrorKind.UNSUPPORTED_CODE, f"authentication method {response[1]:#04x}"
        )
    return MethodReply(method)


def socks5_handshake_no_auth(sock: socket.socket) -> MethodReply | SocksError:
    """Offer no authentication and return the actual selection or read error."""
    return _select_method(sock, AuthMethod.NONE)


def socks5_handshake_password(
    sock: socket.socket, username: str, password: str
) -> AuthenticationResult:
    """Return method selection, subnegotiation status, or an explicit error.

    NeoProxy intentionally acknowledges credential receipt at this stage.
    Its auth.basic_auth middleware verifies the subsequent CONNECT request.
    """
    try:
        user_bytes = username.encode("utf-8")
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError as error:
        return SocksError(ErrorKind.INVALID_INPUT, str(error))
    if len(user_bytes) > 255 or len(password_bytes) > 255:
        return SocksError(
            ErrorKind.INVALID_INPUT, "credentials exceed one-byte lengths"
        )
    selected = _select_method(sock, AuthMethod.PASSWORD)
    if isinstance(selected, SocksError) or selected.method is not AuthMethod.PASSWORD:
        return selected
    request = (
        bytes([1, len(user_bytes)])
        + user_bytes
        + bytes([len(password_bytes)])
        + password_bytes
    )
    error = _send(sock, request)
    if error is not None:
        return error
    response = _read_exact(sock, 2)
    if isinstance(response, SocksError):
        return response
    if response[0] != 1:
        return SocksError(
            ErrorKind.INVALID_VERSION, f"subnegotiation version {response[0]}"
        )
    # RFC 1929 section 2 defines every nonzero status as failure.
    status = AuthStatus.SUCCESS if response[1] == 0 else AuthStatus.FAILURE
    return AuthReply(status)


def _command(sock: socket.socket, request: bytes) -> CommandResult:
    error = _send(sock, request)
    if error is not None:
        return error
    header = _read_exact(sock, 4)
    if isinstance(header, SocksError):
        return header
    if header[0] != VERSION:
        return SocksError(
            ErrorKind.INVALID_VERSION, f"command reply version {header[0]}"
        )
    if header[2] != 0:
        return SocksError(ErrorKind.INVALID_RESERVED, f"reserved byte {header[2]}")
    code = decode_wire(ReplyCode, header[1])
    address_type = decode_wire(AddressType, header[3])
    if code is None:
        return SocksError(
            ErrorKind.UNSUPPORTED_CODE, f"command reply code {header[1]:#04x}"
        )
    if address_type is None:
        return SocksError(
            ErrorKind.UNSUPPORTED_CODE, f"bound address type {header[3]:#04x}"
        )
    if address_type is AddressType.DOMAIN:
        length = _read_exact(sock, 1)
        if isinstance(length, SocksError):
            return length
        size = length[0]
    else:
        size = 4 if address_type is AddressType.IPV4 else 16
    address = _read_exact(sock, size)
    if isinstance(address, SocksError):
        return address
    port = _read_exact(sock, 2)
    if isinstance(port, SocksError):
        return port
    return CommandReply(code, address_type, address, int.from_bytes(port, "big"))


def _addressed_command(
    sock: socket.socket,
    command: Command,
    address_type: AddressType,
    address: bytes,
    port: int,
) -> CommandResult:
    # Check representability only. Tests may intentionally send port 0
    # or an empty domain to verify the server's rejection behavior.
    if not 0 <= port <= 65535:
        return SocksError(ErrorKind.INVALID_INPUT, "port does not fit two bytes")
    if address_type is AddressType.DOMAIN:
        if len(address) > 255:
            return SocksError(ErrorKind.INVALID_INPUT, "domain exceeds one-byte length")
        address = bytes([len(address)]) + address
    request = (
        bytes([VERSION, command.value, 0, address_type.value])
        + address
        + port.to_bytes(2, "big")
    )
    return _command(sock, request)


def socks5_connect_ipv4(
    sock: socket.socket, target_ip: str, target_port: int
) -> CommandResult:
    try:
        address = ipaddress.IPv4Address(target_ip).packed
    except ipaddress.AddressValueError as error:
        return SocksError(ErrorKind.INVALID_INPUT, str(error))
    return _addressed_command(
        sock, Command.CONNECT, AddressType.IPV4, address, target_port
    )


def socks5_connect_ipv6(
    sock: socket.socket, target_ip: str, target_port: int
) -> CommandResult:
    try:
        address = ipaddress.IPv6Address(target_ip).packed
    except ipaddress.AddressValueError as error:
        return SocksError(ErrorKind.INVALID_INPUT, str(error))
    return _addressed_command(
        sock, Command.CONNECT, AddressType.IPV6, address, target_port
    )


def socks5_connect_domain(
    sock: socket.socket, domain: str, target_port: int
) -> CommandResult:
    try:
        address = domain.encode("utf-8")
    except UnicodeEncodeError as error:
        return SocksError(ErrorKind.INVALID_INPUT, str(error))
    return _addressed_command(
        sock, Command.CONNECT, AddressType.DOMAIN, address, target_port
    )


def socks5_send_bind_command(sock: socket.socket) -> CommandResult:
    return _addressed_command(
        sock, Command.BIND, AddressType.IPV4, b"\x7f\x00\x00\x01", 0
    )


def socks5_send_udp_associate(sock: socket.socket) -> CommandResult:
    return _addressed_command(
        sock, Command.UDP_ASSOCIATE, AddressType.IPV4, b"\x00" * 4, 0
    )


def socks5_request_unsupported_method(sock: socket.socket) -> MethodReply | SocksError:
    return _select_method(sock, AuthMethod.GSSAPI)
