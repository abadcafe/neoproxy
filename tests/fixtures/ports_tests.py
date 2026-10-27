"""Public behavior tests for ports."""

import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from tests.fixtures.ports import (
    get_unique_port,
    wait_for_port_released,
)
from tests.fixtures.proxy_process import terminate_process


@dataclass
class ProbeClock:
    elapsed: float = 0

    def monotonic(self) -> float:
        return self.elapsed

    def sleep(self, duration: float) -> None:
        self.elapsed += duration


def test_wait_for_port_released_caps_wait_to_remaining_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = ProbeClock()

    def connect(address: tuple[str, int], timeout: float) -> socket.socket:
        assert address == ("127.0.0.1", 12345)
        assert 0 < timeout <= 0.005
        return socket.socket()

    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    monkeypatch.setattr(time, "sleep", clock.sleep)
    monkeypatch.setattr(socket, "create_connection", connect)
    assert not wait_for_port_released("127.0.0.1", 12345, timeout=0.005, interval=1)
    assert clock.elapsed == 0.005


def test_get_unique_port_coordinates_independent_processes() -> None:
    program = """import json
import sys
from tests.fixtures.ports import get_unique_port

print('ready', flush=True)
assert sys.stdin.readline() == 'go\\n'
ports: list[int] = [get_unique_port() for _ in range(12)]
print(json.dumps(ports))
"""
    with ExitStack() as resources:
        processes: list[subprocess.Popen[bytes]] = []
        for _ in range(4):
            process = resources.enter_context(
                subprocess.Popen(
                    [sys.executable, "-c", program],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
            _ = resources.callback(terminate_process, process)
            assert process.stdout is not None
            assert process.stdout.readline() == b"ready\n"
            processes.append(process)
        for process in processes:
            assert process.stdin is not None
            _ = process.stdin.write(b"go\n")
            process.stdin.flush()
        allocated: list[int] = []
        for process in processes:
            output, errors = process.communicate(timeout=5)
            assert process.returncode == 0, errors.decode()
            allocated.extend(TypeAdapter(list[int]).validate_json(output))
        assert len(allocated) == len(set(allocated)) == 48


def test_wait_for_port_released_supports_ipv6() -> None:
    port = get_unique_port()
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
        listener.bind(("::1", port))
        listener.listen()
        assert not wait_for_port_released("::1", port, timeout=0.05, interval=0.01)
    assert wait_for_port_released("::1", port, timeout=0.1)


def test_get_unique_port_avoids_udp_ports_already_in_use() -> None:
    previous = get_unique_port()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", previous + 1))
        assert get_unique_port() != previous + 1


def test_get_unique_port_excludes_kernel_ephemeral_client_ports() -> None:
    port = get_unique_port()
    kernel_range = Path("/proc/sys/net/ipv4/ip_local_port_range")
    if kernel_range.is_file():
        first, last = (int(value) for value in kernel_range.read_text().split())
        assert not first <= port <= last
    else:
        assert 1024 <= port < 32768
