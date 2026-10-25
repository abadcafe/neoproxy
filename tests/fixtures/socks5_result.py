"""module: socks5_result; responsibility: model SOCKS5 exchange outcomes.
Public operations: ErrorKind, SocksError, MethodReply, AuthReply,
CommandReply, AuthenticationResult, CommandResult.
Data entities: the seven public result types.
Tests: socks5_client_tests.py and typed integration consumers.
"""

from dataclasses import dataclass
from enum import Enum

from .socks5_protocol import AddressType, AuthMethod, AuthStatus, ReplyCode


class ErrorKind(Enum):
    EOF = "unexpected EOF"
    IO = "I/O error"
    INVALID_VERSION = "invalid protocol version"
    INVALID_RESERVED = "nonzero reserved field"
    UNSUPPORTED_CODE = "unsupported field value"
    INVALID_INPUT = "input does not fit wire format"


@dataclass(frozen=True)
class SocksError:
    kind: ErrorKind
    detail: str


@dataclass(frozen=True)
class MethodReply:
    method: AuthMethod


@dataclass(frozen=True)
class AuthReply:
    # This describes the received subnegotiation reply. NeoProxy's
    # SOCKS-to-HTTP adapter still defers actual authentication to CONNECT.
    status: AuthStatus


@dataclass(frozen=True)
class CommandReply:
    code: ReplyCode
    address_type: AddressType
    bound_address: bytes
    bound_port: int


type AuthenticationResult = AuthReply | MethodReply | SocksError
type CommandResult = CommandReply | SocksError
