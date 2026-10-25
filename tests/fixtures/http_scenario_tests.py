"""Public process behavior of configured HTTP proxy scenarios."""

import copy
import socket
from pathlib import Path

import pytest

from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http_scenario import ProxyContext, running_proxy


def echo_config(addresses: list[str] | None) -> ConfigDict:
    listener: ConfigDict = {"name": "main", "kind": "http"}
    if addresses is not None:
        listener["addresses"] = list(addresses)
    return {
        "server_threads": 1,
        "plugins": {"echo": None},
        "listeners": [listener],
        "services": [{"name": "echo", "kind": "echo.echo"}],
        "servers": [{"name": "default", "listeners": ["main"], "service": "echo"}],
    }


def assert_proxy_serves(proxy: ProxyContext) -> None:
    assert proxy.process.poll() is None
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=2) as client:
        client.sendall(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        assert b"200" in client.recv(4096).split(b"\r\n", 1)[0]


@pytest.mark.parametrize(
    "addresses",
    [None, [], ["127.0.0.1:AUTO_PORT"], ["0.0.0.0:AUTO_PORT"]],
)
def test_running_proxy_assigns_port_without_mutating_configuration(
    tmp_path: Path, addresses: list[str] | None
) -> None:
    config = echo_config(addresses)
    original = copy.deepcopy(config)
    with running_proxy(tmp_path, config) as proxy:
        assert_proxy_serves(proxy)
        assert proxy.working_dir == str(tmp_path)
        assert config == original
    assert proxy.process.poll() is not None
    assert proxy.process.stdout is not None and proxy.process.stdout.closed
    assert proxy.process.stderr is not None and proxy.process.stderr.closed


def test_running_proxy_reuses_configuration_for_independent_processes(
    tmp_path: Path,
) -> None:
    config = echo_config(["127.0.0.1:AUTO_PORT"])
    with (
        running_proxy(tmp_path / "first", config) as first,
        running_proxy(tmp_path / "second", config) as second,
    ):
        assert first.port != second.port
        assert_proxy_serves(first)
        assert_proxy_serves(second)
    assert first.process.poll() is not None
    assert second.process.poll() is not None
