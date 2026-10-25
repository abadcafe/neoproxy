"""module: socks5_protocol; responsibility: define SOCKS5 field domains.
Public operations: VERSION, AuthMethod, Command, AddressType, ReplyCode,
AuthStatus, decode_wire.
Data entities: AuthMethod, Command, AddressType, ReplyCode, AuthStatus.
Tests: socks5_protocol_tests.py and client framing tests.
"""

from enum import Enum

VERSION = 5


class AuthMethod(Enum):
    NONE = 0
    GSSAPI = 1
    PASSWORD = 2
    NO_ACCEPTABLE = 255


class Command(Enum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class AddressType(Enum):
    IPV4 = 1
    DOMAIN = 3
    IPV6 = 4


class ReplyCode(Enum):
    SUCCESS = 0
    GENERAL_FAILURE = 1
    CONNECTION_NOT_ALLOWED = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_TYPE_NOT_SUPPORTED = 8


class AuthStatus(Enum):
    SUCCESS = 0
    # RFC 1929 section 2: every nonzero STATUS means failure. This is
    # the semantic result, not an exhaustive enumeration of wire bytes.
    FAILURE = 1


def decode_wire[E: Enum](domain: type[E], value: int) -> E | None:
    """Decode a supported field value without mixing protocol domains."""
    try:
        return domain(value)
    except ValueError:
        # Enum conversion uses ValueError for an unsupported wire value.
        return None
