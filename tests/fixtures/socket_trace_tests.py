"""Kernel socket evidence through the public trace interface."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from tests.fixtures.socket_trace import SocketSample, SocketTrace


def test_socket_trace_records_owned_tcp_and_udp_with_timestamps(tmp_path: Path) -> None:
    output = tmp_path / "sockets.jsonl"
    with (
        socket.socket() as listener,
        socket.socket(type=socket.SOCK_DGRAM) as udp,
    ):
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        udp.bind(("127.0.0.1", 0))
        tcp_address = TypeAdapter(tuple[str, int]).validate_python(
            listener.getsockname()
        )
        udp_address = TypeAdapter(tuple[str, int]).validate_python(udp.getsockname())
        with (
            socket.create_connection(tcp_address) as client,
            SocketTrace(output) as trace,
        ):
            trace.watch(os.getpid())
            client.sendall(b"socket evidence")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                text = output.read_text()
                counters = "txbytes" if sys.platform == "darwin" else "bytes_sent:"
                if (
                    str(udp_address[1]) in text
                    and str(tcp_address[1]) in text
                    and counters in text
                ):
                    break
                time.sleep(0.02)
    samples = [
        SocketSample.model_validate_json(line)
        for line in output.read_text().splitlines()
    ]
    assert {sample.protocol for sample in samples} == {"tcp", "udp"}
    owned = [sample for sample in samples if os.getpid() in sample.process_ids]
    assert owned
    assert all(
        sample.timestamp_ns > 0 and sample.monotonic_ns > 0 for sample in samples
    )
    assert all(sample.returncode == 0 and sample.error is None for sample in samples)
    counters = "txbytes" if sys.platform == "darwin" else "bytes_sent:"
    assert any(counters in sample.output for sample in owned)
    assert any(str(tcp_address[1]) in sample.output for sample in owned)
    assert any(str(udp_address[1]) in sample.output for sample in owned)


def test_socket_trace_does_not_include_unwatched_sockets(tmp_path: Path) -> None:
    output = tmp_path / "sockets.jsonl"
    with SocketTrace(output):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not output.read_text():
            time.sleep(0.02)
    samples = [
        SocketSample.model_validate_json(line)
        for line in output.read_text().splitlines()
    ]
    assert samples
    assert all(not sample.output and not sample.process_ids for sample in samples)


def test_socket_trace_linux_keeps_only_watched_process_sockets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import patch

    monkeypatch.setattr(sys, "platform", "linux")
    output = tmp_path / "linux-sockets.jsonl"
    with patch("tests.fixtures.socket_trace.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(
            ["ss"],
            0,
            stdout=(
                "ESTAB 0 0 127.0.0.1:1234 127.0.0.1:4321 "
                'users:(("proxy",pid=31415,fd=3))\n'
                "    bytes_sent:5\n"
                "ESTAB 0 0 127.0.0.1:2345 127.0.0.1:5432 "
                'users:(("other",pid=27182,fd=3))\n'
                "    bytes_sent:7\n"
            ),
            stderr="",
        )
        with SocketTrace(output) as trace:
            trace.watch(31415)
            deadline = time.monotonic() + 3
            while (
                time.monotonic() < deadline and "bytes_sent:5" not in output.read_text()
            ):
                time.sleep(0.02)
    samples = [
        SocketSample.model_validate_json(line)
        for line in output.read_text().splitlines()
    ]
    owned = [sample for sample in samples if sample.process_ids]
    assert owned
    assert all(
        "pid=31415," in sample.output and "bytes_sent:5" in sample.output
        for sample in owned
    )
    assert all(
        "pid=27182," not in sample.output and "bytes_sent:7" not in sample.output
        for sample in owned
    )
