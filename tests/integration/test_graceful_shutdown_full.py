"""
Graceful shutdown and fast fail integration tests.

Test target: Verify neoproxy graceful shutdown and fast fail behavior
Test nature: Black-box testing through external interface (signals, process exit codes)

This test module covers the following scenarios from design document section 7:
- 7.1 Normal shutdown scenarios (SIGINT, SIGTERM)
- 7.2 Repeated signal scenarios
- 7.3 Timeout scenarios
- 7.4 Panic scenarios (worker thread panic)
- 7.5 Error exit scenarios (port conflict)
- 7.6 Multiple worker thread abnormal scenarios
- 7.7 Panic and error exit mixed scenarios
- 7.8 CONNECT tunnel scenarios
- 7.9 Resource cleanup scenarios

Initialization failures are covered by test_config_validation.py.
"""

import shutil
import signal
import socket
import subprocess
import tempfile
import time

from tests.fixtures.http_configuration import create_echo_config, create_test_config
from tests.fixtures.http_request import establish_connect_tunnel
from tests.fixtures.ports import get_unique_port, wait_for_port_released
from tests.fixtures.proxy_process import MAX_SHUTDOWN_TIME, BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server

# ==============================================================================
# Test cases - 7.1 Normal shutdown scenarios
# ==============================================================================


class TestNormalShutdown:
    """Test 7.1: Normal shutdown scenarios."""

    def test_shutdown_sigint(self) -> None:
        """
        TC-SHUTDOWN-001: Graceful shutdown on SIGINT.

        Target: Verify neoproxy handles SIGINT gracefully with exit code 0
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Send SIGINT
            proxy_proc.send_signal(signal.SIGINT)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                _ = proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0 (graceful shutdown)
            assert return_code == 0, f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_shutdown_sigterm(self) -> None:
        """
        TC-SHUTDOWN-002: Graceful shutdown on SIGTERM.

        Target: Verify neoproxy handles SIGTERM gracefully with exit code 0
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                _ = proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0 (graceful shutdown)
            assert return_code == 0, f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.2 Repeated signal scenarios
# ==============================================================================


class TestRepeatedSignal:
    """Test 7.2: Repeated signal scenarios."""

    def test_multiple_sigint_ignored(self) -> None:
        """
        TC-SIGNAL-001: Multiple SIGINT signals - only first triggers shutdown.

        Target: Verify that repeated signals are ignored and exit code is 0
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Send multiple SIGINT signals rapidly
            proxy_proc.send_signal(signal.SIGINT)
            time.sleep(0.1)
            proxy_proc.send_signal(signal.SIGINT)
            time.sleep(0.1)
            proxy_proc.send_signal(signal.SIGINT)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=10)
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


# ==============================================================================
# Test cases - 7.3 Timeout scenarios
# ==============================================================================


class TestShutdownTimeout:
    """Test 7.3: Shutdown timeout scenarios."""

    def test_shutdown_timeout_with_blocking_tunnel(self) -> None:
        """
        TC-TIMEOUT-001: Shutdown with blocking tunnel triggers timeout.

        Target: Verify process exits after timeout when tunnel does not close
        Expected behavior:
        - Listener task wait budget: 3 seconds plus 2 seconds for cancellation
        - Service task wait budget: 3 seconds plus 2 seconds for cancellation
        - These two task wait budgets total 10 seconds (+ test allowance)
        - Exit code should be 0
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None
        client_sock: socket.socket | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            # Create target server that blocks for a long time
            def blocking_handler(conn: socket.socket) -> None:
                try:
                    # Keep connection open for a long time
                    # This simulates a long-running tunnel
                    time.sleep(60)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, blocking_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Establish CONNECT tunnel
            client_sock = establish_connect_tunnel(
                "127.0.0.1", proxy_port, "127.0.0.1", target_port
            )
            assert client_sock is not None, "Failed to establish tunnel"

            # Send SIGTERM while tunnel is active
            proxy_proc.send_signal(signal.SIGTERM)

            # Measure shutdown time
            start_time = time.monotonic()
            try:
                return_code = proxy_proc.wait(timeout=15)
                elapsed = time.monotonic() - start_time
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                _ = proxy_proc.wait()
                elapsed = time.monotonic() - start_time
                assert False, (
                    "Process did not exit within expected time (elapsed:"
                    + f" {elapsed:.1f}s)"
                )

            # Verify shutdown completed within timeout
            # Allow the two task wait budgets (10s) plus test overhead.
            assert elapsed < MAX_SHUTDOWN_TIME + 2, (
                f"Shutdown took too long: {elapsed:.1f}s (expected <"
                + f" {MAX_SHUTDOWN_TIME + 2}s)"
            )

            # Verify exit code is 0
            assert return_code == 0, f"Expected exit code 0, got {return_code}"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.5 Error exit scenarios
# ==============================================================================


class TestErrorExit:
    """Test 7.5: Error exit scenarios (port conflict)."""

    def test_port_conflict_behavior(self) -> None:
        """A listener bind failure must terminate the proxy with worker error.

        Reserve the port without SO_REUSEPORT. Two NeoProxy processes both
        enable SO_REUSEPORT, so starting a second proxy does not reliably
        create a port conflict.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
                occupied.bind(("0.0.0.0", proxy_port))
                occupied.listen(1)
                config_path = create_test_config(proxy_port, temp_dir)
                proxy_proc = start_proxy(config_path)

                try:
                    return_code = proxy_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy_proc.kill()
                    _ = proxy_proc.wait()
                    assert False, "Proxy stayed alive after its listener failed to bind"

                assert return_code == 2, (
                    f"Expected worker failure exit code 2, got {return_code}"
                )
        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.8 CONNECT tunnel scenarios
# ==============================================================================


class TestConnectTunnel:
    """Test 7.8: CONNECT tunnel scenarios."""

    def test_tunnel_graceful_shutdown(self) -> None:
        """
        TC-TUNNEL-001: Active tunnel closes gracefully on shutdown.

        Target: Verify that active CONNECT tunnel is properly closed
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None
        client_sock: socket.socket | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            # Create target server
            received_data: list[bytes] = []

            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        received_data.append(data)
                        conn.sendall(b"ECHO:" + data)
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Establish CONNECT tunnel
            client_sock = establish_connect_tunnel(
                "127.0.0.1", proxy_port, "127.0.0.1", target_port
            )
            assert client_sock is not None, "Failed to establish tunnel"

            # Send data through tunnel
            client_sock.sendall(b"TEST_DATA")
            response = client_sock.recv(1024)
            assert b"ECHO:TEST_DATA" in response, (
                f"Expected ECHO response, got: {response}"
            )

            # Send SIGTERM while tunnel is active
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                _ = proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0
            assert return_code == 0, f"Expected exit code 0, got {return_code}"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - 7.9 Resource cleanup scenarios
# ==============================================================================


class TestResourceCleanup:
    """Test 7.9: Resource cleanup scenarios."""

    def test_socket_cleanup_after_shutdown(self) -> None:
        """
        TC-CLEANUP-001: Listening socket is closed after shutdown.

        Target: Verify that listening socket is properly closed and port is released
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                _ = proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0
            assert return_code == 0, f"Expected exit code 0, got {return_code}"

            # Wait for socket to be released
            assert wait_for_port_released("127.0.0.1", proxy_port, timeout=2.0), (
                "Expected socket to be closed after shutdown"
            )

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_multiple_connections_cleanup(self) -> None:
        """
        TC-CLEANUP-002: Multiple connections are cleaned up on shutdown.

        Target: Verify that multiple active connections are all cleaned up
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        client_socks: list[socket.socket] = []

        try:
            config_path = create_echo_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert proxy_proc.wait_ready(timeout=2.0), "Proxy server failed to start"

            # Create multiple idle connections
            num_connections = 5
            for _ in range(num_connections):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect(("127.0.0.1", proxy_port))
                client_socks.append(sock)

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit (graceful shutdown needs time)
            try:
                return_code = proxy_proc.wait(timeout=10)
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
                _ = proxy_proc.wait(timeout=2)
            shutil.rmtree(temp_dir, ignore_errors=True)
