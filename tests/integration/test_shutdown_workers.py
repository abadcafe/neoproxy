"""shutdown workers process integration tests."""

import shutil
import signal
import socket
import subprocess
import tempfile
import time

from tests.fixtures.http_configuration import create_test_config
from tests.fixtures.http_request import establish_connect_tunnel
from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server


class TestMultipleWorkerThreads:
    """Test multiple worker threads scenarios."""

    def test_normal_shutdown_with_multiple_workers(self) -> None:
        """
        TC-WORKERS-001: Normal shutdown with multiple worker threads.

        Target: Verify graceful shutdown works with multiple worker threads
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir, server_threads=4)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy(
                "127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc
            ), "Proxy server failed to start"

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                _ = proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0
            assert return_code == 0, f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_shutdown_with_multiple_workers_and_connections(
        self,
    ) -> None:
        """
        TC-WORKERS-002: Shutdown with multiple workers and active connections.

        Target: Verify graceful shutdown with multiple workers handling connections
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None
        client_socks: list[socket.socket] = []

        try:
            config_path = create_test_config(proxy_port, temp_dir, server_threads=4)

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

            assert wait_for_proxy(
                "127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc
            ), "Proxy server failed to start"

            # Establish multiple tunnels
            for _ in range(5):
                sock = establish_connect_tunnel(
                    "127.0.0.1", proxy_port, "127.0.0.1", target_port
                )
                if sock:
                    client_socks.append(sock)

            time.sleep(0.5)

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                _ = proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0
            assert return_code == 0, f"Expected exit code 0, got {return_code}"

        finally:
            for sock in client_socks:
                sock.close()
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
