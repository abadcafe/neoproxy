"""Observe actual child UDP descriptors without depending on Linux procfs."""

import socket
import subprocess
import sys

from pydantic import TypeAdapter

from .ports import get_unique_port
from .proxy_process import BytesProcess
from .udp_sockets import bound_socket_count


def test_bound_socket_count_filters_by_process_and_port() -> None:
    script = """import socket
import sys

first: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
second: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
first.bind(("127.0.0.1", 0))
second.bind(("127.0.0.1", 0))
print(first.getsockname()[1], second.getsockname()[1], flush=True)
_ = sys.stdin.buffer.read(1)
first.close()
second.close()
"""
    process: BytesProcess = subprocess.Popen(
        [sys.executable, "-c", script], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    with process:
        assert process.stdin is not None and process.stdout is not None
        line = TypeAdapter(bytes).validate_python(
            process.stdout.readline(), strict=True
        )
        first, second = (int(port) for port in line.split())
        try:
            assert bound_socket_count(process, first) == 1
            assert bound_socket_count(process, second) == 1
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as parent:
                parent_port = get_unique_port()
                parent.bind(("127.0.0.1", parent_port))
                assert bound_socket_count(process, parent_port) == 0
        finally:
            _ = process.stdin.write(b"x")
            process.stdin.flush()
        assert process.wait(timeout=2) == 0
        assert bound_socket_count(process, first) == 0
