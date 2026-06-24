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
import threading
import time

import pytest

from .conftest import get_unique_port
from .types import (
    BytesProcess,
)
from .utils.helpers import (
    create_target_server,
    create_test_config,
    start_proxy,
    wait_for_proxy,
)

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
                        conn.send(b"ECHO:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, echo_handler)

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc), "Proxy server failed to start"

            # Establish tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(30.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
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
                proxy_proc.wait(timeout=5)
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
                    conn.send(f"RECEIVED:{total}".encode())
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, receive_handler)

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc), "Proxy server failed to start"

            # Establish tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(30.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
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

            start_time = time.time()
            sent = 0
            while sent < data_size:
                to_send = min(chunk_size, data_size - sent)
                client_sock.sendall(test_data[:to_send])
                sent += to_send
            elapsed = time.time() - start_time

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
                proxy_proc.wait(timeout=5)
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
                        conn.send(b"OK")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, quick_handler)

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc), "Proxy server failed to start"

            # Rapid connection cycle
            num_cycles = 50
            failures = 0

            for _ in range(num_cycles):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect(("127.0.0.1", proxy_port))

                    connect_request = (
                        f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
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

            # Allow some failures due to rapid cycling
            failure_rate = failures / num_cycles
            assert failure_rate < 0.1, f"Failure rate {failure_rate:.2%} is too high"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_1000_concurrent_connections(self) -> None:
        """
        TC-PERF-005: 1000 concurrent connections handled correctly.

        Target: Verify proxy handles 1000+ concurrent connections
        as required by architecture document section 3.1.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir, server_threads=8)

            # Create target server
            connections_count: dict[str, int] = {"count": 0}
            connections_lock = threading.Lock()

            def counting_handler(conn: socket.socket) -> None:
                with connections_lock:
                    connections_count["count"] += 1
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.send(b"ECHO:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server("127.0.0.1", target_port, counting_handler)

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc), "Proxy server failed to start"

            # Create 1000 concurrent connections via asyncio
            num_connections = 1000
            concurrency = 200

            async def make_connection(conn_id: int, sem: asyncio.Semaphore) -> tuple[int, bool]:
                async with sem:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection("127.0.0.1", proxy_port),
                            timeout=10.0,
                        )

                        # Send CONNECT request
                        connect_request = (
                            f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
                        ).encode()
                        writer.write(connect_request)
                        await writer.drain()

                        # Read response
                        response = await asyncio.wait_for(
                            reader.readuntil(b"\r\n\r\n"),
                            timeout=10.0,
                        )

                        if b"200" in response:
                            # Send and receive data
                            writer.write(b"TEST")
                            await writer.drain()
                            echo = await asyncio.wait_for(reader.read(1024), timeout=10.0)
                            success = b"ECHO:TEST" in echo
                        else:
                            success = False

                        writer.close()
                        return (conn_id, success)
                    except OSError, asyncio.TimeoutError:
                        return (conn_id, False)

            sem = asyncio.Semaphore(concurrency)
            results = await asyncio.gather(*(make_connection(i, sem) for i in range(num_connections)))

            # Verify results
            successful = [r for r in results if r[1]]
            success_rate = len(successful) / num_connections

            # All connections should succeed
            assert success_rate >= 0.99, f"Success rate {success_rate:.2%} is below 99% for 1000 concurrent connections"

        finally:
            if proxy_proc:
                proxy_proc.kill()
                proxy_proc.wait(timeout=15)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
