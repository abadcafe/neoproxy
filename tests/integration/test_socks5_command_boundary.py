"""Process contracts for the SOCKS5 command and listener boundaries."""

import socket
import subprocess
import time
from pathlib import Path

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.socks5_client import socks5_connect_domain, socks5_handshake_no_auth
from tests.fixtures.socks5_configuration import create_socks5_config
from tests.fixtures.socks5_protocol import AuthMethod, ReplyCode
from tests.fixtures.socks5_result import CommandReply, MethodReply


def test_socks5_command_uses_header_deadline_after_subnegotiation(
    tmp_path: Path,
) -> None:
    port = get_unique_port()
    config = create_socks5_config(port, str(tmp_path), header_read_timeout="300ms")
    process = start_proxy(config)
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            assert socks5_handshake_no_auth(client) == MethodReply(AuthMethod.NONE)
            started = time.monotonic()
            assert client.recv(1) == b""
            assert 0.2 <= time.monotonic() - started < 2
    finally:
        terminate_process(process)
    assert process.returncode == 0
    diagnostics = b"".join(path.read_bytes() for path in (tmp_path / "logs").glob("*"))
    assert b"SOCKS5 command timed out" in diagnostics


def test_socks5_invalid_http_target_fails_connection_and_keeps_worker_alive(
    tmp_path: Path,
) -> None:
    port = get_unique_port()
    config = create_socks5_config(port, str(tmp_path))
    process = start_proxy(config)
    try:
        assert process.wait_ready()
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            assert socks5_handshake_no_auth(client) == MethodReply(AuthMethod.NONE)
            reply = socks5_connect_domain(client, "invalid target", 80)
            assert isinstance(reply, CommandReply)
            assert reply.code is ReplyCode.ADDRESS_TYPE_NOT_SUPPORTED
            assert client.recv(1) == b""
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            assert socks5_handshake_no_auth(client) == MethodReply(AuthMethod.NONE)
        assert process.poll() is None
    finally:
        terminate_process(process)
    assert process.returncode == 0


def test_socks5_partial_bind_failure_fails_process_and_releases_first_address(
    tmp_path: Path,
) -> None:
    first = get_unique_port()
    occupied = get_unique_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", occupied))
        blocker.listen(1)
        config = create_socks5_config(
            first,
            str(tmp_path),
            addresses=[f"127.0.0.1:{first}", f"127.0.0.1:{occupied}"],
        )
        result = subprocess.run(
            [NEOPROXY_BINARY, "--config", config],
            cwd=tmp_path,
            capture_output=True,
            check=False,
            timeout=5,
        )
        # Ordinary worker errors exit with 2; panic exits with 1.
        assert result.returncode == 2
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", first))
