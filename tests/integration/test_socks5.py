"""
SOCKS5 Listener 集成测试

测试目标: 验证 neoproxy SOCKS5 Listener 功能
测试性质: 黑盒测试，通过外部接口验证行为
"""

import shutil
import socket
import tempfile
import threading
import time

from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.socks5_client import (
    socks5_connect_domain,
    socks5_connect_ipv4,
    socks5_connect_ipv6,
    socks5_handshake_no_auth,
    socks5_handshake_password,
    socks5_request_unsupported_method,
    socks5_send_bind_command,
    socks5_send_udp_associate,
)
from tests.fixtures.socks5_configuration import create_socks5_config
from tests.fixtures.socks5_protocol import AuthMethod, AuthStatus, ReplyCode
from tests.fixtures.socks5_result import AuthReply, CommandReply, MethodReply
from tests.fixtures.tcp_peer import create_target_server, send_ok_and_close

# ==============================================================================
# Test Classes
# ==============================================================================


class TestSocks5BasicConnection:
    """Basic SOCKS5 connection tests"""

    def test_no_auth_connection_success(self) -> None:
        """
        TC-S5-001: No authentication mode connection success

        Test that SOCKS5 connection succeeds with no authentication
        and bidirectional data transfer works correctly.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            # Create config (no auth field = no auth required)
            config_path = create_socks5_config(proxy_port, temp_dir)

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

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy(
                "127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc
            ), "Proxy server failed to start"

            # Connect and perform SOCKS5 handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Handshake
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                # Connect to target
                reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, (
                    f"Connect failed with reply code {reply}"
                )

                # Send data and verify echo
                test_data = b"HELLO_SOCKS5"
                sock.sendall(test_data)
                response = sock.recv(1024)
                assert response == b"ECHO:" + test_data, (
                    f"Expected 'ECHO:{test_data}', got: {response}"
                )

            finally:
                sock.close()

            # Verify target received data
            time.sleep(0.2)
            assert any((test_data in d for d in received_data)), (
                "Target server did not receive data"
            )

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_auth_success(self) -> None:
        """
        TC-S5-002: Password authentication mode success

        Test that SOCKS5 connection succeeds with correct credentials.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            # Create config with password auth
            users = [{"username": "testuser", "password": "testpass"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            # Create target server
            def echo_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.sendall(b"OK")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy(
                "127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc
            ), "Proxy server failed to start"

            # Connect and authenticate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Authenticate with correct credentials
                status = socks5_handshake_password(sock, "testuser", "testpass")
                assert isinstance(status, AuthReply)
                assert status.status is AuthStatus.SUCCESS, (
                    f"Authentication failed with status {status}"
                )

                # Connect to target
                reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, (
                    f"Connect failed with reply code {reply}"
                )

                # Send data and verify
                sock.sendall(b"TEST")
                response = sock.recv(1024)
                assert response == b"OK", f"Expected 'OK', got: {response}"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_auth_failure(self) -> None:
        """
        TC-S5-003: Password authentication failure

        Test that SOCKS5 connection fails with wrong credentials.
        The server rejects credentials during RFC 1929 subnegotiation.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            # Create config with password auth
            users = [{"username": "testuser", "password": "correctpass"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy(
                "127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc
            ), "Proxy server failed to start"

            # Connect and try wrong password
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                status = socks5_handshake_password(sock, "testuser", "wrongpass")
                assert isinstance(status, AuthReply)
                assert status.status is AuthStatus.FAILURE
                assert sock.recv(1) == b""

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_unsupported_auth_method(self) -> None:
        """
        TC-S5-004: Unsupported authentication method

        Test that server returns METHOD=0xFF when client requests
        an authentication method not supported by server.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            # Create config with password auth
            users = [{"username": "testuser", "password": "testpass"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy(
                "127.0.0.1", proxy_port, timeout=5.0, proc=proxy_proc
            ), "Proxy server failed to start"

            # Request unsupported method (GSSAPI)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                method = socks5_request_unsupported_method(sock)
                assert isinstance(method, MethodReply)
                assert method.method is AuthMethod.NO_ACCEPTABLE, (
                    f"Expected METHOD=0xFF, got {method}"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5UnsupportedCommands:
    """Tests for unsupported SOCKS5 commands"""

    def test_bind_command_not_supported(self) -> None:
        """
        TC-S5-005: BIND command returns error

        Test that BIND command returns REP=0x07 (command not supported).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                reply = socks5_send_bind_command(sock)
                assert isinstance(reply, CommandReply)
                assert reply.code is not ReplyCode.SUCCESS, "BIND command should fail"
                assert reply.code is ReplyCode.COMMAND_NOT_SUPPORTED, (
                    f"Expected REP=0x07, got {reply}"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_udp_associate_not_supported(self) -> None:
        """
        TC-S5-006: UDP ASSOCIATE command returns error

        Test that UDP ASSOCIATE command returns REP=0x07 (command not supported).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                reply = socks5_send_udp_associate(sock)
                assert isinstance(reply, CommandReply)
                assert reply.code is not ReplyCode.SUCCESS, (
                    "UDP ASSOCIATE command should fail"
                )
                assert reply.code is ReplyCode.COMMAND_NOT_SUPPORTED, (
                    f"Expected REP=0x07, got {reply}"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5TargetAddressTypes:
    """Tests for different target address types"""

    def test_ipv4_target_address(self) -> None:
        """
        TC-S5-010: IPv4 target address

        Test connection to IPv4 target address.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.sendall(b"IPV4_OK")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, (
                    f"Connect failed with reply code {reply}"
                )

                sock.sendall(b"TEST")
                response = sock.recv(1024)
                assert response == b"IPV4_OK", f"Got: {response}"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_ipv6_target_address(self) -> None:
        """
        TC-S5-011: IPv6 target address

        Test connection to IPv6 target address (localhost ::1).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.sendall(b"IPV6_OK")
                except OSError:
                    pass
                finally:
                    conn.close()

            # Create IPv6 target server
            target_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            target_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            target_socket.bind(("::1", target_port))
            target_socket.listen(5)

            def accept_loop() -> None:
                try:
                    target_socket.settimeout(5.0)
                    conn = target_socket.accept()[0]
                    echo_handler(conn)
                except OSError:
                    pass

            thread = threading.Thread(target=accept_loop)
            thread.daemon = True
            thread.start()

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                reply = socks5_connect_ipv6(sock, "::1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, (
                    f"Connect failed with reply code {reply}"
                )

                sock.sendall(b"TEST")
                response = sock.recv(1024)
                assert response == b"IPV6_OK", f"Got: {response}"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_domain_target_address(self) -> None:
        """
        TC-S5-012: Domain target address with DNS resolution

        Test connection to domain target address (localhost).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.sendall(b"DOMAIN_OK")
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                # Use localhost domain
                reply = socks5_connect_domain(sock, "localhost", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, (
                    f"Connect failed with reply code {reply}"
                )

                sock.sendall(b"TEST")
                response = sock.recv(1024)
                assert response == b"DOMAIN_OK", f"Got: {response}"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5ConnectionTarget:
    """Tests for connection target success/failure scenarios"""

    def test_connection_success(self) -> None:
        """
        TC-S5-013: Connection to target success

        Test that Service sends REP=0x00 on successful connection.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            _, target_socket = create_target_server(
                "127.0.0.1",
                target_port,
                send_ok_and_close,
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is ReplyCode.SUCCESS, (
                    f"Expected success, got reply {reply}"
                )
                assert reply.code is ReplyCode.SUCCESS, (
                    f"Expected REP=0x00, got {reply}"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_connection_refused(self) -> None:
        """
        TC-S5-014: Connection refused

        Test that Service sends REP=0x05 when target refuses connection.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            # Don't create target server - port should be unavailable

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert isinstance(reply, CommandReply)
                assert reply.code is not ReplyCode.SUCCESS, "Connection should fail"
                assert reply.code is ReplyCode.CONNECTION_REFUSED, (
                    f"Expected REP=0x05, got {reply}"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5PortBoundary:
    """Tests for port boundary values"""

    def test_port_1(self) -> None:
        """
        TC-S5-015: Port 1 target address

        Test connection to port 1 (minimum valid port).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                # Port 1 - unlikely to have service, should get connection refused
                reply = socks5_connect_ipv4(sock, "127.0.0.1", 1)
                assert isinstance(reply, CommandReply)
                # Should get some error (connection refused most likely)
                assert reply.code is not ReplyCode.SUCCESS, (
                    "Connection to port 1 should fail"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_port_65535(self) -> None:
        """
        TC-S5-016: Port 65535 target address

        Test connection to port 65535 (maximum valid port).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                # Port 65535 - max valid port
                reply = socks5_connect_ipv4(sock, "127.0.0.1", 65535)
                assert isinstance(reply, CommandReply)
                # Should get some error (connection refused most likely)
                assert reply.code is not ReplyCode.SUCCESS, (
                    "Connection to port 65535 should fail"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5DomainBoundary:
    """Tests for domain boundary values"""

    def test_domain_unresolvable(self) -> None:
        """
        TC-S5-020: Unresolvable domain name resolution failure

        Test that a short domain (that won't resolve) returns failure.
        Uses "x.invalid" (RFC 2606 reserved TLD, guaranteed NXDOMAIN)
        instead of single-byte "a" to avoid slow DNS search domain fallback.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy(
                "127.0.0.1", proxy_port, timeout=2.0, proc=proxy_proc
            ), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                # "x.invalid" won't resolve (RFC 2606 reserved TLD)
                reply = socks5_connect_domain(sock, "x.invalid", 80)
                assert isinstance(reply, CommandReply)
                # Will fail because domain won't resolve
                assert reply.code is not ReplyCode.SUCCESS, "Connection should fail"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc, timeout=0.5, force=True)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_domain_255_bytes(self) -> None:
        """
        TC-S5-021: 255-byte domain

        Test connection to 255-byte domain (maximum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                # 255-byte domain (valid length)
                long_domain = "a" * 255
                reply = socks5_connect_domain(sock, long_domain, 80)
                assert isinstance(reply, CommandReply)
                # Will fail because domain won't resolve
                assert reply.code is not ReplyCode.SUCCESS, "Connection should fail"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5AdditionalBoundary:
    """Additional boundary value tests"""

    def test_password_255_bytes(self) -> None:
        """
        TC-S5-033: 255-byte password

        Test authentication with 255-byte password (maximum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            long_password = "x" * 255
            users = [{"username": "test", "password": long_password}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1",
                target_port,
                send_ok_and_close,
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                authentication = socks5_handshake_password(sock, "test", long_password)
                assert isinstance(authentication, AuthReply)
                assert authentication.status is AuthStatus.SUCCESS, (
                    "Authentication with 255-byte password should succeed"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_port_0(self) -> None:
        """
        TC-S5-035: Port 0 target address

        Test connection to port 0 (invalid port).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), (
                "Proxy server failed to start"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                # Port 0 - invalid
                reply = socks5_connect_ipv4(sock, "127.0.0.1", 0)
                assert isinstance(reply, CommandReply)
                # Should fail
                assert reply.code is not ReplyCode.SUCCESS, (
                    "Connection to port 0 should fail"
                )

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)
