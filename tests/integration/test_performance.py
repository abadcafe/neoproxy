"""
Performance integration tests.

Test target: Verify neoproxy performance characteristics
Test nature: Black-box testing through external interface

This test module covers:
- 7.6 Performance scenarios
"""

import subprocess
import socket
import threading
import tempfile
import shutil
import time
import os
import signal
from typing import Optional, Tuple, List, Dict

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    create_test_config,
    terminate_process,
)

from .conftest import get_unique_port


# ==============================================================================
# Test cases - 7.6 Performance scenarios
# ==============================================================================


class TestPerformance:
    """Test 7.6: Performance scenarios."""

    def test_concurrent_connections(self) -> None:
        """
        TC-PERF-001: 100 concurrent connections handled correctly.

        Target: Verify proxy handles 100 concurrent connections
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=4)

            # Create target server
            connections_count: Dict[str, int] = {"count": 0}
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
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, counting_handler
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Create 100 concurrent connections
            num_connections = 100
            results: List[Tuple[int, bool]] = []
            results_lock = threading.Lock()

            def make_connection(conn_id: int) -> None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10.0)
                    sock.connect(("127.0.0.1", proxy_port))

                    # Send CONNECT request
                    connect_request = (
                        f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{target_port}\r\n\r\n"
                    ).encode()
                    sock.sendall(connect_request)

                    # Read response
                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        response += chunk

                    if b"200" in response:
                        # Send and receive data
                        sock.sendall(b"TEST")
                        echo = sock.recv(1024)
                        success = b"ECHO:TEST" in echo
                    else:
                        success = False

                    sock.close()
                    with results_lock:
                        results.append((conn_id, success))
                except Exception:
                    with results_lock:
                        results.append((conn_id, False))

            threads: List[threading.Thread] = []
            for i in range(num_connections):
                t = threading.Thread(target=make_connection, args=(i,))
                threads.append(t)

            # Start all threads
            for t in threads:
                t.start()

            # Wait for all threads
            for t in threads:
                t.join(timeout=30)

            # Verify results
            successful = [r for r in results if r[1]]
            success_rate = len(successful) / num_connections

            assert success_rate >= 0.95, \
                f"Success rate {success_rate:.2%} is below 95%"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_long_running_connection(self) -> None:
        """
        TC-PERF-002: Long-running connection remains stable.

        Target: Verify connection stays stable for extended duration
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None
        client_sock: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        conn.send(b"ECHO:" + data)
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Establish tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(30.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n\r\n"
            ).encode()
            client_sock.sendall(connect_request)

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = client_sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            assert b"200" in response, "Failed to establish tunnel"

            # Send data multiple times over 5 seconds
            for i in range(10):
                test_data = f"TEST_{i}".encode()
                client_sock.sendall(test_data)
                echo = client_sock.recv(1024)
                assert b"ECHO:" + test_data in echo, \
                    f"Echo failed at iteration {i}"
                time.sleep(0.5)

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
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
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None
        client_sock: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            received_data: List[bytes] = []

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
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, receive_handler
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Establish tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(30.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n\r\n"
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
            assert b"RECEIVED:" in result, \
                f"Target did not confirm receipt: {result}"

            # Verify throughput (should be at least 1MB/s on localhost)
            throughput = data_size / elapsed / 1024 / 1024  # MB/s
            assert throughput >= 1.0, \
                f"Throughput {throughput:.2f} MB/s is too low"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
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
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            def quick_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.send(b"OK")
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, quick_handler
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Rapid connection cycle
            num_cycles = 50
            failures = 0

            for i in range(num_cycles):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect(("127.0.0.1", proxy_port))

                    connect_request = (
                        f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{target_port}\r\n\r\n"
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
                except Exception:
                    failures += 1

            # Allow some failures due to rapid cycling
            failure_rate = failures / num_cycles
            assert failure_rate < 0.1, \
                f"Failure rate {failure_rate:.2%} is too high"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_1000_concurrent_connections(self) -> None:
        """
        TC-PERF-005: 1000 concurrent connections handled correctly.

        Target: Verify proxy handles 1000+ concurrent connections
        as required by architecture document section 3.1.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=8)

            # Create target server
            connections_count: Dict[str, int] = {"count": 0}
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
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, counting_handler
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Create 1000 concurrent connections
            num_connections = 1000
            results: List[Tuple[int, bool]] = []
            results_lock = threading.Lock()

            def make_connection(conn_id: int) -> None:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(30.0)
                    sock.connect(("127.0.0.1", proxy_port))

                    # Send CONNECT request
                    connect_request = (
                        f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{target_port}\r\n\r\n"
                    ).encode()
                    sock.sendall(connect_request)

                    # Read response
                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        response += chunk

                    if b"200" in response:
                        # Send and receive data
                        sock.sendall(b"TEST")
                        echo = sock.recv(1024)
                        success = b"ECHO:TEST" in echo
                    else:
                        success = False

                    sock.close()
                    with results_lock:
                        results.append((conn_id, success))
                except Exception:
                    with results_lock:
                        results.append((conn_id, False))

            threads: List[threading.Thread] = []
            for i in range(num_connections):
                t = threading.Thread(target=make_connection, args=(i,))
                threads.append(t)

            # Start all threads in batches to avoid overwhelming the system
            batch_size = 100
            for i in range(0, len(threads), batch_size):
                batch = threads[i:i+batch_size]
                for t in batch:
                    t.start()
                time.sleep(0.1)  # Small delay between batches

            # Wait for all threads
            for t in threads:
                t.join(timeout=60)

            # Verify results
            successful = [r for r in results if r[1]]
            success_rate = len(successful) / num_connections

            # Allow lower success rate for 1000 connections (90% minimum)
            assert success_rate >= 0.90, \
                f"Success rate {success_rate:.2%} is below 90% for 1000 concurrent connections"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=15)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)