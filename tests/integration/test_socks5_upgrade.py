"""
SOCKS5 CONNECT Proxy - Black-box Tests

Verifies SOCKS5 CONNECT proxy behavior:
1. SOCKS5 CONNECT still works end-to-end (data transfer)
2. SOCKS5 error responses are correctly sent for unreachable targets
3. Concurrent SOCKS5 connections work

HTTP CONNECT regression testing is covered separately in test_http_connect.py.
"""

import os
import shutil
import socket
import tempfile

from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.socks5_client import (
    socks5_connect_domain,
    socks5_connect_ipv4,
    socks5_handshake_no_auth,
)
from tests.fixtures.socks5_protocol import AuthMethod, ReplyCode
from tests.fixtures.socks5_result import CommandReply, MethodReply
from tests.fixtures.tcp_peer import create_target_server


def create_socks5_connect_tcp_config(
    proxy_port: int,
    temp_dir: str,
) -> str:
    """Create a minimal SOCKS5 + connect_tcp config using the real schema."""
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks5_main
  kind: socks5
  addresses:
    - "127.0.0.1:{proxy_port}"

servers:
- name: socks5_server
  listeners: ["socks5_main"]
  service: direct
"""
    config_path = os.path.join(temp_dir, "config.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


# REP field


# REP field


class TestSocks5UpgradeConnectTcp:
    """Test SOCKS5 CONNECT through connect_tcp service."""

    temp_dir: str = ""
    processes: list[BytesProcess] = []
    sockets: list[socket.socket] = []

    def setup_method(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="neoproxy_upgrade_test_")
        self.processes = []
        self.sockets = []

    def teardown_method(self) -> None:
        for proc in self.processes:
            terminate_process(proc)
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _start_proxy(self, port: int) -> None:
        config = create_socks5_connect_tcp_config(port, self.temp_dir)
        proc = start_proxy(config)
        self.processes.append(proc)
        assert wait_for_proxy("127.0.0.1", port, timeout=10.0), (
            "Proxy did not start in time"
        )

    def _create_echo_target(self, port: int) -> None:
        """Create a TCP echo server on the given port."""

        def handler(conn: socket.socket) -> None:
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            except OSError:
                pass
            finally:
                conn.close()

        _, server_sock = create_target_server("127.0.0.1", port, handler)
        self.sockets.append(server_sock)

    def _get_closed_port(self) -> int:
        """Get a port guaranteed to refuse connections.

        Uses port 1 which is reserved and never has a listening service,
        ensuring immediate connection refused on all platforms.
        """
        return 1

    def test_socks5_connect_ipv4_bidirectional_transfer(self) -> None:
        """SOCKS5 CONNECT to IPv4 target with bidirectional data transfer."""
        proxy_port = get_unique_port()
        target_port = get_unique_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
        assert isinstance(rep, CommandReply)
        assert rep.code is ReplyCode.SUCCESS, f"Expected success, got REP={rep}"

        # Bidirectional transfer
        test_data = b"Hello from SOCKS5 upgrade test!"
        sock.sendall(test_data)
        echoed = sock.recv(4096)
        assert echoed == test_data, f"Echo mismatch: {echoed!r}"

    def test_socks5_connect_domain_bidirectional_transfer(self) -> None:
        """SOCKS5 CONNECT to domain target with bidirectional data transfer."""
        proxy_port = get_unique_port()
        target_port = get_unique_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE)
        rep = socks5_connect_domain(sock, "127.0.0.1", target_port)
        assert isinstance(rep, CommandReply)
        assert rep.code is ReplyCode.SUCCESS, f"Expected success, got REP={rep}"

        test_data = b"Domain target test data"
        sock.sendall(test_data)
        echoed = sock.recv(4096)
        assert echoed == test_data, f"Echo mismatch: {echoed!r}"

    def test_socks5_connect_refused_target(self) -> None:
        """SOCKS5 CONNECT to a port with no listener returns error reply."""
        proxy_port = get_unique_port()
        # Get a port that is guaranteed to refuse connections
        closed_port = self._get_closed_port()

        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", closed_port)
        assert isinstance(rep, CommandReply)
        # Should get a non-zero error reply (connection refused or general failure)
        assert rep.code is not ReplyCode.SUCCESS, (
            f"Expected error reply for refused connection, got REP={rep}"
        )

    def test_socks5_connect_refused_error_code(self) -> None:
        """SOCKS5 CONNECT to refused port returns REP=0x05 (Connection Refused).

        Per RFC 1928 section 6, when the target host refuses the connection,
        the SOCKS5 proxy should reply with REP=0x05 (Connection refused).
        """
        proxy_port = get_unique_port()
        closed_port = self._get_closed_port()

        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", closed_port)
        assert isinstance(rep, CommandReply)
        assert rep.code is ReplyCode.CONNECTION_REFUSED, (
            f"Expected REP=0x05 (Connection Refused), got REP={rep}"
        )

    def test_socks5_concurrent_connections(self) -> None:
        """Multiple concurrent SOCKS5 connections work independently."""
        proxy_port = get_unique_port()
        target_port = get_unique_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        connections: list[socket.socket] = []
        for i in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            self.sockets.append(sock)
            sock.connect(("127.0.0.1", proxy_port))
            assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE)
            rep = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
            assert isinstance(rep, CommandReply)
            assert rep.code is ReplyCode.SUCCESS
            connections.append(sock)

        # Send different data on each connection
        for i, sock in enumerate(connections):
            data = f"conn-{i}-data".encode()
            sock.sendall(data)
            echoed = sock.recv(4096)
            assert echoed == data, f"Connection {i} echo mismatch"

    def test_socks5_large_data_transfer(self) -> None:
        """SOCKS5 tunnel handles large data transfer correctly."""
        proxy_port = get_unique_port()
        target_port = get_unique_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        assert socks5_handshake_no_auth(sock) == MethodReply(AuthMethod.NONE)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
        assert isinstance(rep, CommandReply)
        assert rep.code is ReplyCode.SUCCESS

        # Send 64KB of data
        test_data = b"X" * 65536
        sock.sendall(test_data)

        received = b""
        while len(received) < len(test_data):
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
        assert received == test_data, (
            f"Large transfer mismatch: got {len(received)} bytes"
        )
