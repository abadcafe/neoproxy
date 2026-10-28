"""Process contracts for accept recovery under child-only FD exhaustion."""

import errno
import signal
import socket
import ssl
import time
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.http_configuration import create_echo_config
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process

type ListenerKind = Literal["http", "https", "socks5"]


@contextmanager
def running_proxy(
    directory: Path, listener_kind: ListenerKind, retry_delay: str | None
) -> Generator[tuple[BytesProcess, int]]:
    port = get_unique_port()
    config = Path(create_echo_config(port, str(directory)))
    content = config.read_text().replace("  kind: http\n", f"  kind: {listener_kind}\n")
    if retry_delay is not None:
        content = content.replace(
            f"  kind: {listener_kind}\n",
            f"  kind: {listener_kind}\n" + f"  tcp_accept_retry_delay: {retry_delay}\n",
        )
    if listener_kind == "https":
        cert, key, _, _ = generate_test_certificates(str(directory))
        content += (
            f"  certificates:\n  - cert_path: {cert}\n" + f"    key_path: {key}\n"
        )
    _ = config.write_text(content)
    process = start_proxy(str(config), nofile_limit=64)
    try:
        assert process.wait_ready()
        yield process, port
    finally:
        # The descriptor limit is restricted to this disposable child.
        terminate_process(process, timeout=2, force=True)


def wait_for_accept_failure(directory: Path, process: BytesProcess) -> str:
    deadline = time.monotonic() + 3
    output = ""
    while time.monotonic() < deadline:
        output = "".join(
            path.read_text() for path in (directory / "logs").glob("neoproxy.log.*")
        )
        if "accept failed; retrying after backoff" in output:
            return output
        assert process.poll() is None, output
        time.sleep(0.01)
    assert False, f"accept did not report FD exhaustion: {output}"


@contextmanager
def exhausted_connections(port: int) -> Generator[None]:
    # Leave protocol handshakes incomplete so accepted sockets occupy the
    # child's descriptor table. Additional sockets wait in its listen backlog.
    with ExitStack() as connections:
        for _ in range(128):
            _ = connections.enter_context(
                socket.create_connection(("127.0.0.1", port), timeout=3)
            )
        yield


@pytest.mark.parametrize("listener_kind", ["http", "https", "socks5"])
@pytest.mark.parametrize("retry_delay", [None, "250ms"])
def test_accept_recovers_after_file_descriptors_are_released(
    tmp_path: Path, listener_kind: ListenerKind, retry_delay: str | None
) -> None:
    with running_proxy(tmp_path, listener_kind, retry_delay) as (process, port):
        with exhausted_connections(port):
            output = wait_for_accept_failure(tmp_path, process)
            assert "ERROR" in output
            assert f"address=0.0.0.0:{port}" in output
            assert f"os error {errno.EMFILE}" in output
            assert f"retry_delay={retry_delay or '1s'}" in output
            assert process.poll() is None
        # Closing the accepted sessions releases descriptors without needing
        # Linux-only APIs to change another process's limits.
        with ExitStack() as sockets:
            connection = sockets.enter_context(
                socket.create_connection(("127.0.0.1", port), timeout=3)
            )
            if listener_kind == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = sockets.enter_context(
                    context.wrap_socket(connection, server_hostname="localhost")
                )
            reader = sockets.enter_context(connection.makefile("rb"))
            if listener_kind == "socks5":
                connection.sendall(b"\x05\x01\x00")
                assert reader.read(2) == b"\x05\x00"
            else:
                connection.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                assert reader.readline().startswith(b"HTTP/1.1 200 ")
            assert process.poll() is None


@pytest.mark.parametrize("listener_kind", ["http", "https", "socks5"])
def test_accept_shutdown_interrupts_resource_backoff(
    tmp_path: Path, listener_kind: ListenerKind
) -> None:
    with running_proxy(tmp_path, listener_kind, "30s") as (process, port):
        with exhausted_connections(port):
            output = wait_for_accept_failure(tmp_path, process)
            assert "retry_delay=30s" in output
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=2) == 0
