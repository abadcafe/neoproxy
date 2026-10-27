"""socks5 lifecycle process integration tests."""

import shutil
import signal
import socket
import tempfile
import time

from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.socks5_client import socks5_connect_ipv4, socks5_handshake_no_auth
from tests.fixtures.socks5_configuration import create_socks5_config
from tests.fixtures.socks5_protocol import VERSION, AuthMethod, ReplyCode
from tests.fixtures.socks5_result import CommandReply, MethodReply
from tests.fixtures.tcp_peer import create_target_server, send_ok_and_close


class TestSocks5MultiAddress:
    """Tests for multiple listening addresses"""

    def test_multiple_addresses(self) -> None:
        """
        TC-S5-022: Multiple listening addresses

        Test that SOCKS5 listener works on multiple addresses.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port1 = get_unique_port()
        proxy_port2 = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            # Listen on two addresses
            addresses = [
                f"0.0.0.0:{proxy_port1}",
                f"0.0.0.0:{proxy_port2}",
            ]
            config_path = create_socks5_config(
                proxy_port1, temp_dir, addresses=addresses
            )

            _, target_socket = create_target_server(
                "127.0.0.1",
                target_port,
                send_ok_and_close,
            )

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(timeout=5.0), (
                "Proxy server failed to start on port 1"
            )
            assert proxy_proc.wait_ready(timeout=5.0), (
                "Proxy server failed to start on port 2"
            )

            # Test first address
            sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock1.settimeout(10.0)
            try:
                sock1.connect(("127.0.0.1", proxy_port1))
                assert socks5_handshake_no_auth(sock1) == MethodReply(
                    AuthMethod.NONE
                ), "Handshake failed on port 1"
                reply = socks5_connect_ipv4(sock1, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, "Connection failed on port 1"
            finally:
                sock1.close()

            # Test second address
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(10.0)
            try:
                sock2.connect(("127.0.0.1", proxy_port2))
                assert socks5_handshake_no_auth(sock2) == MethodReply(
                    AuthMethod.NONE
                ), "Handshake failed on port 2"
                reply = socks5_connect_ipv4(sock2, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, "Connection failed on port 2"
            finally:
                sock2.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5ClientDisconnect:
    """Tests for client disconnect scenarios"""

    def test_disconnect_during_handshake(self) -> None:
        """
        TC-S5-024: Client disconnect during handshake

        Test that server handles client disconnect during handshake gracefully.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            # Connect and disconnect immediately
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                # Send partial handshake
                sock.sendall(bytes([VERSION, 1, AuthMethod.NONE.value]))
                # Immediately close
            finally:
                sock.close()

            # Server should still be running
            assert proxy_proc.wait_ready(timeout=2.0), (
                "Server should still accept connections after client disconnect"
            )

            # Try another connection
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(10.0)
            try:
                sock2.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock2) == MethodReply(
                    AuthMethod.NONE
                ), "Server should still work"
            finally:
                sock2.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5GracefulShutdown:
    """Tests for graceful shutdown"""

    def test_graceful_shutdown(self) -> None:
        """
        TC-S5-025: Graceful shutdown

        Test that server shuts down gracefully with active connections.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def blocking_handler(conn: socket.socket) -> None:
                try:
                    # Keep connection open
                    time.sleep(10)
                    conn.sendall(b"DONE")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, blocking_handler
            )

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(timeout=5.0), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )
                reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, "Connection failed"

                # Give server time to shutdown
                time.sleep(0.5)

                # Send SIGTERM
                proxy_proc.send_signal(signal.SIGTERM)

                # Wait for process to exit
                exit_code = proxy_proc.wait(timeout=15)
                assert exit_code == 0, f"Expected exit code 0, got {exit_code}"

            finally:
                sock.close()

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
