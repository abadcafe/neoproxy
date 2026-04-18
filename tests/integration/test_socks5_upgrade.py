"""
SOCKS5 CONNECT Proxy - Black-box Tests

Verifies SOCKS5 CONNECT proxy behavior:
1. SOCKS5 CONNECT still works end-to-end (data transfer)
2. SOCKS5 error responses are correctly sent for unreachable targets
3. Concurrent SOCKS5 connections work

HTTP CONNECT regression testing is covered separately in test_http_connect.py.
"""

import os
import socket
import struct
import subprocess
import tempfile
import shutil

from .utils.helpers import (
    start_proxy,
    wait_for_proxy,
    create_target_server,
    terminate_process,
)


# SOCKS5 constants
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_CONNECTION_REFUSED = 0x05


def create_socks5_connect_tcp_config(
    proxy_port: int,
    temp_dir: str,
) -> str:
    """Create a minimal SOCKS5 + connect_tcp config using the real schema."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: socks5_server
  listeners:
  - kind: fast_socks5.listener
    args:
      addresses:
        - "127.0.0.1:{proxy_port}"
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a socket, handling partial TCP reads.

    TCP does not guarantee that recv(N) returns N bytes even for small
    reads. This helper loops until all n bytes are received or the
    connection is closed.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def socks5_handshake_no_auth(sock: socket.socket) -> None:
    """Perform SOCKS5 handshake with no authentication."""
    # Send greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH
    sock.sendall(bytes([SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE]))
    # Receive method selection
    resp = recv_exact(sock, 2)
    assert len(resp) >= 2, f"Short handshake response: {len(resp)} bytes"
    assert resp[0] == SOCKS5_VERSION, f"Expected SOCKS5 version, got {resp[0]}"
    assert resp[1] == SOCKS5_AUTH_NONE, f"Expected no auth, got {resp[1]}"


def socks5_connect_ipv4(
    sock: socket.socket,
    host: str,
    port: int,
) -> int:
    """Send SOCKS5 CONNECT request for IPv4 target. Returns reply code."""
    ip_bytes = socket.inet_aton(host)
    # VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST.ADDR, DST.PORT
    req = bytes([SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_IPV4])
    req += ip_bytes + struct.pack("!H", port)
    sock.sendall(req)
    # Read reply (10 bytes for IPv4: VER, REP, RSV, ATYP, 4-byte addr, 2-byte port)
    reply = recv_exact(sock, 10)
    assert len(reply) >= 10, f"Short SOCKS5 reply: {len(reply)} bytes"
    assert reply[0] == SOCKS5_VERSION
    return reply[1]  # REP field


def socks5_connect_domain(
    sock: socket.socket,
    domain: str,
    port: int,
) -> int:
    """Send SOCKS5 CONNECT request for domain target. Returns reply code."""
    domain_bytes = domain.encode("ascii")
    req = bytes([SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_DOMAIN])
    req += bytes([len(domain_bytes)]) + domain_bytes + struct.pack("!H", port)
    sock.sendall(req)
    # Read reply header (4 bytes: VER, REP, RSV, ATYP)
    header = recv_exact(sock, 4)
    assert len(header) >= 4, f"Short SOCKS5 reply header: {len(header)} bytes"
    assert header[0] == SOCKS5_VERSION
    # Read the remaining bind address + port based on ATYP
    # so leftover bytes don't pollute subsequent data transfer.
    atyp = header[3]
    if atyp == SOCKS5_ATYP_IPV4:
        # 4 bytes IPv4 addr + 2 bytes port
        recv_exact(sock, 6)
    elif atyp == SOCKS5_ATYP_DOMAIN:
        # 1 byte domain len + domain bytes + 2 bytes port
        domain_len_buf = recv_exact(sock, 1)
        if domain_len_buf:
            recv_exact(sock, domain_len_buf[0] + 2)
    elif atyp == SOCKS5_ATYP_IPV6:
        # 16 bytes IPv6 addr + 2 bytes port
        recv_exact(sock, 18)
    return header[1]  # REP field


class TestSocks5UpgradeConnectTcp:
    """Test SOCKS5 CONNECT through connect_tcp service."""

    def setup_method(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="neoproxy_upgrade_test_")
        self.processes: list[subprocess.Popen] = []
        self.sockets: list[socket.socket] = []

    def teardown_method(self) -> None:
        for proc in self.processes:
            terminate_process(proc)
        for sock in self.sockets:
            try:
                sock.close()
            except Exception:
                pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _start_proxy(self, port: int) -> None:
        config = create_socks5_connect_tcp_config(port, self.temp_dir)
        proc = start_proxy(config)
        self.processes.append(proc)
        assert wait_for_proxy("127.0.0.1", port, timeout=10.0), \
            "Proxy did not start in time"

    def _create_echo_target(self, port: int) -> None:
        """Create a TCP echo server on the given port."""
        def handler(conn: socket.socket) -> None:
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            except Exception:
                pass
            finally:
                conn.close()

        _, server_sock = create_target_server("127.0.0.1", port, handler)
        self.sockets.append(server_sock)

    def _get_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _get_closed_port(self) -> int:
        """Get a port guaranteed to refuse connections.

        Binds a socket to port 0 (OS-assigned), reads the port number,
        and keeps the socket bound (but NOT listening). This prevents
        the TOCTOU race where another process could grab the port
        between _get_free_port() releasing it and the proxy trying
        to connect. A bound-but-not-listening socket causes
        ConnectionRefused for any connection attempt.

        The socket is registered in self.sockets for cleanup.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        # Do NOT call listen() -- this ensures connection attempts are refused
        self.sockets.append(sock)
        return port

    def test_socks5_connect_ipv4_bidirectional_transfer(self) -> None:
        """SOCKS5 CONNECT to IPv4 target with bidirectional data transfer."""
        proxy_port = self._get_free_port()
        target_port = self._get_free_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        socks5_handshake_no_auth(sock)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
        assert rep == SOCKS5_REP_SUCCESS, f"Expected success, got REP={rep}"

        # Bidirectional transfer
        test_data = b"Hello from SOCKS5 upgrade test!"
        sock.sendall(test_data)
        echoed = sock.recv(4096)
        assert echoed == test_data, f"Echo mismatch: {echoed!r}"

    def test_socks5_connect_domain_bidirectional_transfer(self) -> None:
        """SOCKS5 CONNECT to domain target with bidirectional data transfer."""
        proxy_port = self._get_free_port()
        target_port = self._get_free_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        socks5_handshake_no_auth(sock)
        rep = socks5_connect_domain(sock, "localhost", target_port)
        assert rep == SOCKS5_REP_SUCCESS, f"Expected success, got REP={rep}"

        test_data = b"Domain target test data"
        sock.sendall(test_data)
        echoed = sock.recv(4096)
        assert echoed == test_data, f"Echo mismatch: {echoed!r}"

    def test_socks5_connect_refused_target(self) -> None:
        """SOCKS5 CONNECT to a port with no listener returns error reply."""
        proxy_port = self._get_free_port()
        # Get a port that is guaranteed to refuse connections
        closed_port = self._get_closed_port()

        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        socks5_handshake_no_auth(sock)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", closed_port)
        # Should get a non-zero error reply (connection refused or general failure)
        assert rep != SOCKS5_REP_SUCCESS, \
            f"Expected error reply for refused connection, got REP={rep}"

    def test_socks5_connect_refused_error_code(self) -> None:
        """SOCKS5 CONNECT to refused port returns REP=0x05 (Connection Refused).

        Per RFC 1928 section 6, when the target host refuses the connection,
        the SOCKS5 proxy should reply with REP=0x05 (Connection refused).
        """
        proxy_port = self._get_free_port()
        closed_port = self._get_closed_port()

        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        socks5_handshake_no_auth(sock)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", closed_port)
        assert rep == SOCKS5_REP_CONNECTION_REFUSED, \
            f"Expected REP=0x05 (Connection Refused), got REP={rep}"

    def test_socks5_concurrent_connections(self) -> None:
        """Multiple concurrent SOCKS5 connections work independently."""
        proxy_port = self._get_free_port()
        target_port = self._get_free_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        connections = []
        for i in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            self.sockets.append(sock)
            sock.connect(("127.0.0.1", proxy_port))
            socks5_handshake_no_auth(sock)
            rep = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
            assert rep == SOCKS5_REP_SUCCESS
            connections.append(sock)

        # Send different data on each connection
        for i, sock in enumerate(connections):
            data = f"conn-{i}-data".encode()
            sock.sendall(data)
            echoed = sock.recv(4096)
            assert echoed == data, f"Connection {i} echo mismatch"

    def test_socks5_large_data_transfer(self) -> None:
        """SOCKS5 tunnel handles large data transfer correctly."""
        proxy_port = self._get_free_port()
        target_port = self._get_free_port()

        self._create_echo_target(target_port)
        self._start_proxy(proxy_port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        self.sockets.append(sock)
        sock.connect(("127.0.0.1", proxy_port))

        socks5_handshake_no_auth(sock)
        rep = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
        assert rep == SOCKS5_REP_SUCCESS

        # Send 64KB of data
        test_data = b"X" * 65536
        sock.sendall(test_data)

        received = b""
        while len(received) < len(test_data):
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
        assert received == test_data, \
            f"Large transfer mismatch: got {len(received)} bytes"
