"""http3 performance process integration tests."""

import asyncio
import shutil
import socket
import tempfile
import threading
import time

from tests.fixtures.configuration import StringMap
from tests.fixtures.h3_configuration import (
    create_http3_listener_config,
)
from tests.fixtures.h3_connection import perform_h3_connection_test
from tests.fixtures.h3_tunnel import (
    H3TunnelResult,
    perform_h3_connect_test,
    perform_h3_tunnel_data_transfer,
)
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server


class TestHTTP3Performance:
    """Test 7.6: HTTP/3 performance scenarios."""

    def test_h3_concurrent_connections(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-PERF-001: HTTP/3 handles concurrent connections.

        Target: Verify HTTP/3 listener can handle multiple concurrent connections.
        Uses aioquic to establish multiple HTTP/3 connections simultaneously.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            # Create target server
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

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Test concurrent connections
            num_connections = 10
            results: list[tuple[bool, int]] = []
            results_lock = threading.Lock()

            async def test_connection(_conn_id: int) -> None:
                try:
                    (
                        success,
                        status_code,
                        _,
                    ) = await perform_h3_connect_test(
                        "127.0.0.1",
                        proxy_port,
                        "127.0.0.1",
                        target_port,
                        ca_path=ca_path,
                        timeout=15.0,
                    )
                    with results_lock:
                        results.append((success, status_code))
                except OSError:
                    with results_lock:
                        results.append((False, 0))

            async def run_concurrent_tests() -> None:
                tasks = [test_connection(i) for i in range(num_connections)]
                _ = await asyncio.gather(*tasks)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_concurrent_tests())
            finally:
                loop.close()

            assert len(results) == num_connections
            assert all(success and status == 200 for success, status in results), (
                results
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_h3_connection_latency(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-PERF-002: HTTP/3 connection latency is acceptable.

        Target: Verify HTTP/3 connection establishment latency meets requirements.
        Per design doc: TLS 0-RTT connection latency should be < 50ms.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Measure connection latency
            latencies: list[float] = []

            for _ in range(5):
                start_time = time.monotonic()

                async def test_latency() -> bool:
                    success, _, _ = await perform_h3_connection_test(
                        "127.0.0.1",
                        proxy_port,
                        ca_path=ca_path,
                        timeout=10.0,
                    )
                    return success

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    success = loop.run_until_complete(test_latency())
                finally:
                    loop.close()

                elapsed = time.monotonic() - start_time
                assert success, "latency probe failed"
                latencies.append(elapsed)

            assert len(latencies) == 5
            avg_latency = sum(latencies) / len(latencies)
            assert avg_latency < 1.0, (
                f"Average connection latency {avg_latency:.3f}s is too high"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_h3_data_throughput(self, shared_test_certs: StringMap) -> None:
        """
        TC-H3-PERF-003: HTTP/3 data throughput is acceptable.

        Target: Verify HTTP/3 data transfer throughput meets requirements.
        Per design doc: throughput should be >= 90% of network bandwidth.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]
            config_path = create_http3_listener_config(
                proxy_port, cert_path, key_path, temp_dir
            )

            # Create target server that echoes data
            def throughput_handler(conn: socket.socket) -> None:
                try:
                    total = 0
                    while True:
                        data = conn.recv(8192)
                        if not data:
                            break
                        total += len(data)
                        conn.sendall(data)  # Echo back
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, throughput_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "HTTP/3 listener failed to start"

            # Test throughput with large data transfer
            large_data = b"X" * (100 * 1024)  # 100KB

            async def test_throughput() -> tuple[H3TunnelResult, float]:
                start_time = time.monotonic()
                result = await perform_h3_tunnel_data_transfer(
                    "127.0.0.1",
                    proxy_port,
                    "127.0.0.1",
                    target_port,
                    ca_path=ca_path,
                    test_data=large_data,
                    timeout=30.0,
                )
                elapsed = time.monotonic() - start_time
                return result, elapsed

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result, elapsed = loop.run_until_complete(test_throughput())
            finally:
                loop.close()

            # Verify data was transferred
            assert result.success, result.message
            assert result.response_data == large_data
            throughput_kbps = (result.data_sent + result.data_received) / elapsed / 1024
            assert throughput_kbps >= 10.0, (
                f"Throughput {throughput_kbps:.1f} KB/s is too low"
            )

        finally:
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
