"""
SOCKS5 Listener 集成测试

测试目标: 验证 neoproxy SOCKS5 Listener 功能
测试性质: 黑盒测试，通过外部接口验证行为

握手方法及认证由 test_socks5_method_selection.py 和 test_socks5_credentials.py
覆盖；这里保留命令拒绝、目标地址编码和边界值，不能用正常请求矩阵替代。
"""

import shutil
import socket
import tempfile
import threading

from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.socks5_client import (
    socks5_connect_domain,
    socks5_connect_ipv4,
    socks5_connect_ipv6,
    socks5_handshake_no_auth,
    socks5_send_bind_command,
    socks5_send_udp_associate,
)
from tests.fixtures.socks5_configuration import create_socks5_config
from tests.fixtures.socks5_protocol import AuthMethod, ReplyCode
from tests.fixtures.socks5_result import CommandReply, MethodReply
from tests.fixtures.tcp_peer import create_target_server

# ==============================================================================
# Test Classes
# ==============================================================================


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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

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
        TC-S5-012: Domain address type carrying a numeric loopback target

        Test the domain wire format without depending on system DNS.
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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE), (
                    "Handshake failed"
                )

                reply = socks5_connect_domain(sock, "127.0.0.1", target_port)
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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

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


class TestSocks5AdditionalBoundary:
    """Additional boundary value tests"""

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
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

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
