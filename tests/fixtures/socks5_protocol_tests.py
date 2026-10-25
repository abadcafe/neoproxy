"""Value-domain contracts for the SOCKS5 test protocol."""

from tests.fixtures.socks5_protocol import AuthMethod, AuthStatus, ReplyCode


def test_equal_wire_values_belong_to_distinct_protocol_domains() -> None:
    assert len({AuthMethod.NONE, AuthStatus.SUCCESS, ReplyCode.SUCCESS}) == 3
