"""
Graceful shutdown integration tests.

Test target: Verify neoproxy graceful shutdown behavior
Test nature: Black-box testing through external interface (signals)
"""

import subprocess
import socket
import threading
import tempfile
import shutil
import time
import os
import signal
from typing import Optional, Tuple


# ==============================================================================
# Test helper functions
# ==============================================================================


NEOPROXY_BINARY = "target/debug/neoproxy"


def create_test_config(proxy_port: int, temp_dir: str) -> str:
    """
    Create test configuration file.

    Args:
        proxy_port: Port for the proxy server
        temp_dir: Temporary directory for logs

    Returns:
        str: Path to the configuration file
    """
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http_connect
  listeners:
  - kind: hyper.listener
    args:
      addresses: [ "0.0.0.0:{proxy_port}" ]
      protocols: [ http ]
      hostnames: []
      certificates: []
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "test_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_echo_config(proxy_port: int, temp_dir: str) -> str:
    """
    Create echo service configuration file.

    Args:
        proxy_port: Port for the proxy server
        temp_dir: Temporary directory for logs

    Returns:
        str: Path to the configuration file
    """
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: echo_server
  listeners:
  - kind: hyper.listener
    args:
      addresses: [ "0.0.0.0:{proxy_port}" ]
      protocols: [ http ]
      hostnames: []
      certificates: []
  service: echo
"""
    config_path = os.path.join(temp_dir, "echo_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def start_proxy(config_path: str) -> subprocess.Popen:
    """
    Start proxy server process.

    Args:
        config_path: Path to configuration file

    Returns:
        subprocess.Popen: Proxy server process
    """
    proc = subprocess.Popen(
        [NEOPROXY_BINARY, "--config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False
    )
    return proc


def wait_for_proxy(
    host: str,
    port: int,
    timeout: float = 5.0,
    interval: float = 0.1
) -> bool:
    """
    Wait for proxy server to be ready.

    Args:
        host: Proxy server host
        port: Proxy server port
        timeout: Maximum wait time in seconds
        interval: Check interval in seconds

    Returns:
        bool: True if server is ready, False if timeout
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def create_target_server(
    host: str,
    port: int,
    handler
) -> Tuple[threading.Thread, socket.socket]:
    """
    Create a mock target server.

    Args:
        host: Listen address
        port: Listen port
        handler: Connection handler function

    Returns:
        Tuple[threading.Thread, socket.socket]: Server thread and socket
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    running = threading.Event()
    running.set()

    def server_loop() -> None:
        while running.is_set():
            try:
                server_socket.settimeout(0.5)
                conn, _ = server_socket.accept()
                thread = threading.Thread(target=handler, args=(conn,))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception:
                break

    thread = threading.Thread(target=server_loop)
    thread.daemon = True
    thread.start()

    return thread, server_socket


# ==============================================================================
# Test cases
# ==============================================================================


class TestGracefulShutdown:
    """Graceful shutdown integration tests."""

    def test_graceful_shutdown_sigint(self) -> None:
        """
        TC-SHUTDOWN-001: Graceful shutdown on SIGINT.

        Target: Verify neoproxy handles SIGINT gracefully
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 28080
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Send SIGINT
            proxy_proc.send_signal(signal.SIGINT)

            # Wait for process to exit (should complete within 5 seconds)
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0 (graceful shutdown)
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

            # Check stderr for shutdown log
            stderr = proxy_proc.stderr.read().decode('utf-8', errors='ignore') if proxy_proc.stderr else ""
            # Note: Logs go to file, so we might not see them in stderr

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_graceful_shutdown_sigterm(self) -> None:
        """
        TC-SHUTDOWN-002: Graceful shutdown on SIGTERM.

        Target: Verify neoproxy handles SIGTERM gracefully
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 28081
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit (should complete within 5 seconds)
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0 (graceful shutdown)
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_shutdown_with_idle_connections(self) -> None:
        """
        TC-SHUTDOWN-003: Shutdown with idle HTTP connections.

        Target: Verify idle connections are properly closed during shutdown
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 28082
        proxy_proc: Optional[subprocess.Popen] = None
        client_sock: Optional[socket.socket] = None

        try:
            config_path = create_echo_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Create an idle HTTP connection
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(5.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            # Keep connection open without sending data (idle)

            # Give it a moment
            time.sleep(0.5)

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_shutdown_with_active_tunnel(self) -> None:
        """
        TC-SHUTDOWN-004: Shutdown with active CONNECT tunnel.

        Target: Verify active tunnel is properly closed during shutdown
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 28083
        target_port = 28084
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None
        client_sock: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            # Create target server
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

            # Establish CONNECT tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(5.0)
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n\r\n"
            ).encode()
            client_sock.sendall(connect_request)

            # Read 200 response
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = client_sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            assert b"200" in response, \
                f"Expected 200 response, got: {response.decode(errors='ignore')}"

            # Send some data to make tunnel active
            client_sock.sendall(b"TEST_DATA")

            # Wait briefly
            time.sleep(0.3)

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, "Process did not exit within expected time"

            # Verify exit code is 0 (graceful shutdown completed)
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_shutdown_timeout(self) -> None:
        """
        TC-SHUTDOWN-005: Shutdown timeout with long-running request.

        Target: Verify process exits after 5 second timeout
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 28085
        target_port = 28086
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None
        client_sock: Optional[socket.socket] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)

            # Create target server that blocks for a long time
            def blocking_handler(conn: socket.socket) -> None:
                try:
                    # Keep connection open for a long time
                    # This simulates a long-running request
                    time.sleep(30)
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, blocking_handler
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Establish CONNECT tunnel
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(10.0)  # Longer timeout for client
            client_sock.connect(("127.0.0.1", proxy_port))

            connect_request = (
                f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{target_port}\r\n\r\n"
            ).encode()
            client_sock.sendall(connect_request)

            # Read 200 response
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = client_sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            # Send SIGTERM while tunnel is active (target server is blocking)
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            # Should exit within 5 seconds (graceful shutdown timeout)
            # Plus some buffer for cleanup
            start_time = time.time()
            try:
                return_code = proxy_proc.wait(timeout=15)
                elapsed = time.time() - start_time
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                elapsed = time.time() - start_time
                assert False, f"Process did not exit within expected time (elapsed: {elapsed:.1f}s)"

            # Verify process exited within reasonable time (5s timeout + buffer)
            assert elapsed < 10, \
                f"Process took too long to exit: {elapsed:.1f}s (expected < 10s)"

            # Verify exit code is 0 (shutdown completed, even if timed out)
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if client_sock:
                client_sock.close()
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)