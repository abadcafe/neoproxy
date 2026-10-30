"""
Performance integration tests.

Test target: Verify neoproxy performance characteristics
Test nature: Black-box testing through external interface

This test module covers:
- 7.6 Performance scenarios
"""

import asyncio
import shutil
import socket
import tempfile
import time
from pathlib import Path

import pytest

from tests.fixtures.http_configuration import create_test_config
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.stream_cleanup import close_writer
from tests.fixtures.tcp_peer import create_target_server

# ==============================================================================
# Test cases - 7.6 Performance scenarios
# ==============================================================================


class TestPerformance:
    """Test 7.6: Performance scenarios."""

    def test_long_running_connection(self) -> None:
        """
        TC-PERF-002: Long-running connection remains stable.

        Target: Verify connection stays stable for extended duration
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None
        client_sock: socket.socket | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.sendall(b"ECHO:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            # Establish tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(30.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost:"
                + f" 127.0.0.1:{target_port}\r\n\r\n"
            ).encode()
            client_sock.sendall(connect_request)

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = client_sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            assert b"200" in response, "Failed to establish tunnel"

            # Send data 1000 times to verify long-running stability
            for i in range(1000):
                test_data = f"TEST_{i}".encode()
                client_sock.sendall(test_data)
                echo = client_sock.recv(1024)
                assert b"ECHO:" + test_data in echo, f"Echo failed at iteration {i}"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_large_data_transfer(self) -> None:
        """
        TC-PERF-003: Large data transfer throughput.

        Target: Verify large data can be transferred efficiently
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None
        client_sock: socket.socket | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            received_data: list[bytes] = []

            def receive_handler(conn: socket.socket) -> None:
                try:
                    total = 0
                    while True:
                        data = conn.recv(8192)
                        if not data:
                            break
                        total += len(data)
                        received_data.append(data)
                    conn.sendall(f"RECEIVED:{total}".encode())
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, receive_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            # Establish tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(30.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost:"
                + f" 127.0.0.1:{target_port}\r\n\r\n"
            ).encode()
            client_sock.sendall(connect_request)

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = client_sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            assert b"200" in response, "Failed to establish tunnel"

            # Send 1MB of data
            data_size = 1024 * 1024  # 1MB
            chunk_size = 8192
            test_data = b"X" * chunk_size

            start_time = time.monotonic()
            sent = 0
            while sent < data_size:
                to_send = min(chunk_size, data_size - sent)
                client_sock.sendall(test_data[:to_send])
                sent += to_send
            elapsed = time.monotonic() - start_time

            # Close write side
            client_sock.shutdown(socket.SHUT_WR)

            # Get response
            result = client_sock.recv(1024)
            assert b"RECEIVED:" in result, f"Target did not confirm receipt: {result}"

            # Verify throughput (should be at least 1MB/s on localhost)
            throughput = data_size / elapsed / 1024 / 1024  # MB/s
            assert throughput >= 1.0, f"Throughput {throughput:.2f} MB/s is too low"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_rapid_connection_cycle(self) -> None:
        """
        TC-PERF-004: Rapid connection open/close cycle.

        Target: Verify proxy handles rapid connection cycling
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            def quick_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.sendall(b"OK")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, quick_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            # Rapid connection cycle
            num_cycles = 50
            failures = 0

            for _ in range(num_cycles):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect(("127.0.0.1", proxy_port))

                    connect_request = (
                        f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost:"
                        + f" 127.0.0.1:{target_port}\r\n\r\n"
                    ).encode()
                    sock.sendall(connect_request)

                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        response += chunk

                    if b"200" not in response:
                        failures += 1

                    sock.close()
                except OSError:
                    failures += 1

            assert failures == 0, (
                f"{failures}/{num_cycles} rapid connection cycles failed"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_1000_concurrent_connections(self, tmp_path: Path) -> None:
        """Hold 1000 real tunnels open together before permitting any to close."""
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        config = create_test_config(proxy_port, str(tmp_path), server_threads=8)
        origins_ready = asyncio.Barrier(1000)
        clients_ready = asyncio.Barrier(1000)
        active = 0
        peak = 0

        async with asyncio.TaskGroup() as origins:

            async def echo(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                nonlocal active, peak
                active += 1
                peak = max(peak, active)
                try:
                    _ = await origins_ready.wait()
                    while data := await reader.read(1024):
                        writer.write(data)
                        await writer.drain()
                finally:
                    active -= 1
                    await close_writer(writer)

            def accept(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                _ = origins.create_task(echo(reader, writer))

            server = await asyncio.start_server(
                accept, "127.0.0.1", target_port, backlog=1024
            )
            async with server:
                process = start_proxy(config)
                try:
                    assert process.wait_ready()

                    async def exchange(index: int) -> None:
                        reader, writer = await asyncio.open_connection(
                            "127.0.0.1", proxy_port
                        )
                        try:
                            writer.write(
                                (
                                    f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                                    f"Host: 127.0.0.1:{target_port}\r\n\r\n"
                                ).encode()
                            )
                            await writer.drain()
                            headers = await reader.readuntil(b"\r\n\r\n")
                            assert headers.split(b"\r\n", 1)[0].split()[1] == b"200"
                            _ = await clients_ready.wait()
                            payload = f"connection-{index}".encode()
                            writer.write(payload)
                            await writer.drain()
                            assert await reader.readexactly(len(payload)) == payload
                        finally:
                            await close_writer(writer)

                    async with asyncio.TaskGroup() as clients:
                        for index in range(1000):
                            _ = clients.create_task(exchange(index))
                    assert peak == 1000
                finally:
                    terminate_process(process)
        assert active == 0
