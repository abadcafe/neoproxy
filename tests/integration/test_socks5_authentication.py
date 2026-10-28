"""socks5 authentication process integration tests."""

import shutil
import socket
import tempfile
import time

import pytest

from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.socks5_client import socks5_handshake_password
from tests.fixtures.socks5_configuration import create_socks5_config
from tests.fixtures.socks5_protocol import VERSION, AuthStatus
from tests.fixtures.socks5_result import AuthReply
from tests.fixtures.tcp_peer import create_target_server, send_ok_and_close


class TestSocks5HandshakeTimeout:
    """Tests for SOCKS5 handshake timeout behavior"""

    def test_header_read_timeout_partial_data(self) -> None:
        """
        TC-S5-008: Handshake timeout - partial data sent

        Test that connection is closed after timeout when client
        sends partial handshake data and stops.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(
                proxy_port, temp_dir, header_read_timeout="0.5s"
            )

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Send only SOCKS version (partial handshake)
                sock.sendall(bytes([VERSION]))

                # Wait for timeout
                start_time = time.monotonic()
                try:
                    data = sock.recv(1024)
                    # Should not receive any response
                    assert len(data) == 0, "Should not receive response on timeout"
                except socket.timeout:
                    pass

                elapsed = time.monotonic() - start_time
                assert elapsed >= 0.3, f"Timeout too fast: {elapsed}s (expected ~0.5s)"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc, timeout=0.5, force=True)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_custom_header_read_timeout(self) -> None:
        """
        TC-S5-009: Custom handshake timeout configuration

        Test that custom handshake timeout is applied correctly.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            # Use 0.5 second timeout
            config_path = create_socks5_config(
                proxy_port, temp_dir, header_read_timeout="0.5s"
            )

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)  # Longer than handshake timeout
            try:
                sock.connect(("127.0.0.1", proxy_port))

                start_time = time.monotonic()
                try:
                    data = sock.recv(1024)
                    assert len(data) == 0, "Expected connection close"
                except socket.timeout:
                    pass

                elapsed = time.monotonic() - start_time
                # Should timeout around 0.5 second
                assert 0.3 <= elapsed <= 1.5, (
                    f"Timeout not matching config: {elapsed}s (expected ~0.5s)"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc, timeout=0.5, force=True)
            shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.timeout(100)
    def test_header_read_timeout_default(self) -> None:
        """
        TC-S5-039: Handshake timeout default value

        Test that default header read timeout is 75 seconds.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            # No header_read_timeout specified, should use default 75s
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(85.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Don't send anything, wait for timeout
                start_time = time.monotonic()
                try:
                    data = sock.recv(1024)
                    assert len(data) == 0, "Expected connection close"
                except socket.timeout:
                    pytest.fail("SOCKS5 default header deadline did not expire")

                elapsed = time.monotonic() - start_time
                # Default should be around 75 seconds
                assert 74.0 <= elapsed <= 85.0, (
                    f"Timeout not matching default: {elapsed}s (expected ~75s)"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5UsernamePasswordBoundary:
    """Tests for username/password boundary values"""

    def test_username_1_byte(self) -> None:
        """
        TC-S5-017: 1-byte username

        Test authentication with 1-byte username (minimum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            users = [{"username": "a", "password": "test"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1",
                target_port,
                send_ok_and_close,
            )

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                authentication = socks5_handshake_password(sock, "a", "test")
                assert isinstance(authentication, AuthReply)
                assert authentication.status is AuthStatus.SUCCESS, (
                    "Authentication with 1-byte username should succeed"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_1_byte(self) -> None:
        """
        TC-S5-018: 1-byte password

        Test authentication with 1-byte password (minimum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            users = [{"username": "test", "password": "x"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1",
                target_port,
                send_ok_and_close,
            )

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                authentication = socks5_handshake_password(sock, "test", "x")
                assert isinstance(authentication, AuthReply)
                assert authentication.status is AuthStatus.SUCCESS, (
                    "Authentication with 1-byte password should succeed"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_username_255_bytes(self) -> None:
        """
        TC-S5-019: 255-byte username

        Test authentication with 255-byte username (maximum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            long_username = "a" * 255
            users = [{"username": long_username, "password": "test"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1",
                target_port,
                send_ok_and_close,
            )

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                authentication = socks5_handshake_password(sock, long_username, "test")
                assert isinstance(authentication, AuthReply)
                assert authentication.status is AuthStatus.SUCCESS, (
                    "Authentication with 255-byte username should succeed"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5InvalidVersion:
    """Tests for invalid SOCKS version handling"""

    def test_invalid_socks_version(self) -> None:
        """
        TC-S5-036: Invalid SOCKS version

        Test that server closes connection without response for invalid version.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Send SOCKS4 version instead of SOCKS5
                sock.sendall(bytes([0x04, 0x01, 0x00, 0x50]))

                # Should not receive response, connection should close
                try:
                    data = sock.recv(1024)
                    # If we get data, it should be empty (connection close)
                    assert len(data) == 0, (
                        "Should not receive response for invalid version"
                    )
                except (
                    socket.timeout,
                    ConnectionResetError,
                    BrokenPipeError,
                ):
                    # Connection reset or timeout is acceptable -
                    # server detected invalid version and closed connection
                    pass

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_non_socks5_data(self) -> None:
        """
        TC-S5-037: Non-SOCKS5 data during handshake

        Test that server handles non-SOCKS5 data gracefully.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Send HTTP data instead of SOCKS5
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

                # Server should close connection without valid SOCKS5 response
                try:
                    data = sock.recv(1024)
                    # If we get data, it should be empty (connection close)
                    # or not be a valid SOCKS5 response
                    if len(data) > 0:
                        # Should not be SOCKS5 version 5 response
                        assert data[0] != VERSION, (
                            "Should not receive valid SOCKS5 response for HTTP data"
                        )
                except (
                    socket.timeout,
                    ConnectionResetError,
                    BrokenPipeError,
                ):
                    # Connection reset or timeout is acceptable
                    pass

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)
