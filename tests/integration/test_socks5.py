"""
SOCKS5 Listener 集成测试

测试目标: 验证 neoproxy SOCKS5 Listener 功能
测试性质: 黑盒测试，通过外部接口验证行为
"""

import subprocess
import socket
import struct
import threading
import tempfile
import shutil
import time
import os
import signal
from typing import Callable, Tuple, List, Dict, Optional

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    terminate_process,
)


# ==============================================================================
# Constants
# ==============================================================================

# SOCKS5 constants
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_PASSWORD = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF

# SOCKS5 commands
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_BIND = 0x02
SOCKS5_CMD_UDP_ASSOCIATE = 0x03

# SOCKS5 address types
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04

# SOCKS5 reply codes
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_GENERAL_FAILURE = 0x01
SOCKS5_REP_CONNECTION_NOT_ALLOWED = 0x02
SOCKS5_REP_NETWORK_UNREACHABLE = 0x03
SOCKS5_REP_HOST_UNREACHABLE = 0x04
SOCKS5_REP_CONNECTION_REFUSED = 0x05
SOCKS5_REP_TTL_EXPIRED = 0x06
SOCKS5_REP_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

# Password auth status
PASSWORD_AUTH_SUCCESS = 0x00
PASSWORD_AUTH_FAILURE = 0x01


# ==============================================================================
# Configuration Helpers
# ==============================================================================


def create_socks5_config(
    proxy_port: int,
    temp_dir: str,
    auth_type: Optional[str] = None,
    users: Optional[List[Dict[str, str]]] = None,
    addresses: Optional[List[str]] = None,
    handshake_timeout: Optional[str] = None,
    worker_threads: int = 1
) -> str:
    """
    Create SOCKS5 listener configuration file.

    Args:
        proxy_port: Port for the SOCKS5 listener
        temp_dir: Temporary directory for logs
        auth_type: Authentication type ("password" or None for no auth)
        users: List of user dicts with "username" and "password" keys
        addresses: List of addresses to listen on (default: ["0.0.0.0:port"])
        handshake_timeout: Handshake timeout string (e.g., "10s")
        worker_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    if addresses is None:
        addresses = [f"0.0.0.0:{proxy_port}"]

    auth_section = ""
    if auth_type == "password" and users:
        users_yaml = "\n".join([
            f"          - username: \"{u['username']}\"\n            password: \"{u['password']}\""
            for u in users
        ])
        auth_section = f"""
      auth:
        users:
{users_yaml}"""

    timeout_section = ""
    if handshake_timeout:
        timeout_section = f"\n      handshake_timeout: \"{handshake_timeout}\""

    config_content = f"""worker_threads: {worker_threads}
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
{chr(10).join([f'        - "{a}"' for a in addresses])}{timeout_section}{auth_section}
  service: connect_tcp
"""

    config_path = os.path.join(temp_dir, "socks5_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# SOCKS5 Protocol Helpers
# ==============================================================================


def socks5_handshake_no_auth(sock: socket.socket) -> bool:
    """
    Perform SOCKS5 handshake with no authentication.

    Args:
        sock: Socket connected to SOCKS5 server

    Returns:
        bool: True if handshake succeeded (method 0x00 selected)
    """
    # Send: VER=5, NMETHODS=1, METHOD=0x00
    sock.send(bytes([SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE]))

    # Receive: VER=5, METHOD
    response = sock.recv(2)
    if len(response) < 2:
        return False
    return response[0] == SOCKS5_VERSION and response[1] == SOCKS5_AUTH_NONE


def socks5_handshake_password(
    sock: socket.socket,
    username: str,
    password: str
) -> Tuple[bool, int]:
    """
    Perform SOCKS5 handshake with username/password authentication.

    Args:
        sock: Socket connected to SOCKS5 server
        username: Username for authentication
        password: Password for authentication

    Returns:
        Tuple[bool, int]: (success, auth_status)
    """
    # Send: VER=5, NMETHODS=1, METHOD=0x02
    sock.send(bytes([SOCKS5_VERSION, 0x01, SOCKS5_AUTH_PASSWORD]))

    # Receive: VER=5, METHOD
    response = sock.recv(2)
    if len(response) < 2:
        return False, -1

    if response[1] != SOCKS5_AUTH_PASSWORD:
        return False, response[1]

    # Send username/password auth (RFC 1929)
    # VER=1, ULEN, UNAME, PLEN, PASSWD
    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")

    auth_request = bytes([0x01, len(username_bytes)]) + username_bytes + \
                   bytes([len(password_bytes)]) + password_bytes
    sock.send(auth_request)

    # Receive: VER=1, STATUS
    auth_response = sock.recv(2)
    if len(auth_response) < 2:
        return False, -1

    return auth_response[1] == PASSWORD_AUTH_SUCCESS, auth_response[1]


def socks5_connect_ipv4(
    sock: socket.socket,
    target_ip: str,
    target_port: int
) -> Tuple[bool, int]:
    """
    Send SOCKS5 CONNECT command with IPv4 address.

    Args:
        sock: Socket after successful handshake
        target_ip: Target IPv4 address
        target_port: Target port

    Returns:
        Tuple[bool, int]: (success, reply_code)
    """
    # Parse IPv4 address
    ip_parts = [int(x) for x in target_ip.split(".")]

    # Send: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, DST.ADDR, DST.PORT
    request = bytes([
        SOCKS5_VERSION,
        SOCKS5_CMD_CONNECT,
        0x00,
        SOCKS5_ATYP_IPV4,
        ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3],
        (target_port >> 8) & 0xFF,
        target_port & 0xFF
    ])
    sock.send(request)

    # Receive: VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT
    response = sock.recv(10)
    if len(response) < 2:
        return False, -1

    return response[1] == SOCKS5_REP_SUCCESS, response[1]


def socks5_connect_ipv6(
    sock: socket.socket,
    target_ip: str,
    target_port: int
) -> Tuple[bool, int]:
    """
    Send SOCKS5 CONNECT command with IPv6 address.

    Args:
        sock: Socket after successful handshake
        target_ip: Target IPv6 address
        target_port: Target port

    Returns:
        Tuple[bool, int]: (success, reply_code)
    """
    # Parse IPv6 address
    import ipaddress
    ip_bytes = ipaddress.IPv6Address(target_ip).packed

    # Send: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv6, DST.ADDR (16 bytes), DST.PORT
    request = bytes([
        SOCKS5_VERSION,
        SOCKS5_CMD_CONNECT,
        0x00,
        SOCKS5_ATYP_IPV6
    ]) + ip_bytes + bytes([
        (target_port >> 8) & 0xFF,
        target_port & 0xFF
    ])
    sock.send(request)

    # Receive: VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT
    response = sock.recv(22)
    if len(response) < 2:
        return False, -1

    return response[1] == SOCKS5_REP_SUCCESS, response[1]


def socks5_connect_domain(
    sock: socket.socket,
    domain: str,
    target_port: int
) -> Tuple[bool, int]:
    """
    Send SOCKS5 CONNECT command with domain name.

    Args:
        sock: Socket after successful handshake
        domain: Target domain name
        target_port: Target port

    Returns:
        Tuple[bool, int]: (success, reply_code)
    """
    domain_bytes = domain.encode("utf-8")

    # Send: VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN, DOMAIN_LEN, DOMAIN, PORT
    request = bytes([
        SOCKS5_VERSION,
        SOCKS5_CMD_CONNECT,
        0x00,
        SOCKS5_ATYP_DOMAIN,
        len(domain_bytes)
    ]) + domain_bytes + bytes([
        (target_port >> 8) & 0xFF,
        target_port & 0xFF
    ])
    sock.send(request)

    # Receive: VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT
    # Minimum response is 10 bytes for IPv4 bind address
    response = sock.recv(256)
    if len(response) < 2:
        return False, -1

    return response[1] == SOCKS5_REP_SUCCESS, response[1]


def socks5_send_bind_command(sock: socket.socket) -> Tuple[bool, int]:
    """
    Send SOCKS5 BIND command (not supported).

    Args:
        sock: Socket after successful handshake

    Returns:
        Tuple[bool, int]: (success, reply_code)
    """
    # Send BIND command to localhost:0
    request = bytes([
        SOCKS5_VERSION,
        SOCKS5_CMD_BIND,
        0x00,
        SOCKS5_ATYP_IPV4,
        127, 0, 0, 1,
        0, 0
    ])
    sock.send(request)

    response = sock.recv(10)
    if len(response) < 2:
        return False, -1

    return response[1] == SOCKS5_REP_SUCCESS, response[1]


def socks5_send_udp_associate(sock: socket.socket) -> Tuple[bool, int]:
    """
    Send SOCKS5 UDP ASSOCIATE command (not supported).

    Args:
        sock: Socket after successful handshake

    Returns:
        Tuple[bool, int]: (success, reply_code)
    """
    # Send UDP ASSOCIATE command
    request = bytes([
        SOCKS5_VERSION,
        SOCKS5_CMD_UDP_ASSOCIATE,
        0x00,
        SOCKS5_ATYP_IPV4,
        0, 0, 0, 0,
        0, 0
    ])
    sock.send(request)

    response = sock.recv(10)
    if len(response) < 2:
        return False, -1

    return response[1] == SOCKS5_REP_SUCCESS, response[1]


def socks5_request_unsupported_method(sock: socket.socket) -> int:
    """
    Request an authentication method not supported by server.

    Args:
        sock: Socket connected to SOCKS5 server

    Returns:
        int: Method returned by server (should be 0xFF)
    """
    # Request GSSAPI method (0x01) which is not supported
    sock.send(bytes([SOCKS5_VERSION, 0x01, 0x01]))

    response = sock.recv(2)
    if len(response) < 2:
        return -1

    return response[1]


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
        proxy_port = 29001
        target_port = 29002
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # Create config (no auth field = no auth required)
            config_path = create_socks5_config(proxy_port, temp_dir)

            # Create target server
            received_data: List[bytes] = []

            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        received_data.append(data)
                        conn.send(b"ECHO:" + data)
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Connect and perform SOCKS5 handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Handshake
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                # Connect to target
                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert success, f"Connect failed with reply code {reply}"

                # Send data and verify echo
                test_data = b"HELLO_SOCKS5"
                sock.send(test_data)
                response = sock.recv(1024)
                assert response == b"ECHO:" + test_data, \
                    f"Expected 'ECHO:{test_data}', got: {response}"

            finally:
                sock.close()

            # Verify target received data
            time.sleep(0.2)
            assert any(test_data in d for d in received_data), \
                "Target server did not receive data"

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
        proxy_port = 29003
        target_port = 29004
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

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
                        conn.send(b"OK")
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Connect and authenticate
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Authenticate with correct credentials
                success, status = socks5_handshake_password(
                    sock, "testuser", "testpass"
                )
                assert success, f"Authentication failed with status {status}"

                # Connect to target
                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert success, f"Connect failed with reply code {reply}"

                # Send data and verify
                sock.send(b"TEST")
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
        Note: RFC 1929 allows any non-zero status code for auth failure.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29005
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Create config with password auth
            users = [{"username": "testuser", "password": "correctpass"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Connect and try wrong password
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Try with wrong password
                success, status = socks5_handshake_password(
                    sock, "testuser", "wrongpass"
                )
                assert not success, "Authentication should have failed"
                # RFC 1929: any non-zero status indicates failure
                assert status != PASSWORD_AUTH_SUCCESS, \
                    f"Expected auth failure (non-zero status), got {status}"

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
        proxy_port = 29006
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Create config with password auth
            users = [{"username": "testuser", "password": "testpass"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Request unsupported method (GSSAPI)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                method = socks5_request_unsupported_method(sock)
                assert method == SOCKS5_AUTH_NO_ACCEPTABLE, \
                    f"Expected METHOD=0xFF, got {method}"

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
        proxy_port = 29007
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                assert socks5_handshake_no_auth(sock), "Handshake failed"

                success, reply = socks5_send_bind_command(sock)
                assert not success, "BIND command should fail"
                assert reply == SOCKS5_REP_COMMAND_NOT_SUPPORTED, \
                    f"Expected REP=0x07, got {reply}"

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
        proxy_port = 29008
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                assert socks5_handshake_no_auth(sock), "Handshake failed"

                success, reply = socks5_send_udp_associate(sock)
                assert not success, "UDP ASSOCIATE command should fail"
                assert reply == SOCKS5_REP_COMMAND_NOT_SUPPORTED, \
                    f"Expected REP=0x07, got {reply}"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5HandshakeTimeout:
    """Tests for SOCKS5 handshake timeout behavior"""

    def test_handshake_timeout_no_data(self) -> None:
        """
        TC-S5-007: Handshake timeout - no data sent

        Test that connection is closed after timeout when client
        sends no data. No response should be sent.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29009
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Use 2 second timeout for faster test
            config_path = create_socks5_config(
                proxy_port, temp_dir, handshake_timeout="2s"
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Don't send anything, wait for timeout
                start_time = time.time()
                try:
                    data = sock.recv(1024)
                    # If we receive data, it should be connection close
                    assert len(data) == 0, \
                        "Expected connection close, not response data"
                except socket.timeout:
                    pass

                elapsed = time.time() - start_time
                # Should timeout around 2 seconds
                assert elapsed >= 1.5, \
                    f"Timeout too fast: {elapsed}s (expected ~2s)"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_handshake_timeout_partial_data(self) -> None:
        """
        TC-S5-008: Handshake timeout - partial data sent

        Test that connection is closed after timeout when client
        sends partial handshake data and stops.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29010
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(
                proxy_port, temp_dir, handshake_timeout="2s"
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Send only SOCKS version (partial handshake)
                sock.send(bytes([SOCKS5_VERSION]))

                # Wait for timeout
                start_time = time.time()
                try:
                    data = sock.recv(1024)
                    # Should not receive any response
                    assert len(data) == 0, \
                        "Should not receive response on timeout"
                except socket.timeout:
                    pass

                elapsed = time.time() - start_time
                assert elapsed >= 1.5, \
                    f"Timeout too fast: {elapsed}s (expected ~2s)"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_custom_handshake_timeout(self) -> None:
        """
        TC-S5-009: Custom handshake timeout configuration

        Test that custom handshake timeout is applied correctly.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29011
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Use 3 second timeout
            config_path = create_socks5_config(
                proxy_port, temp_dir, handshake_timeout="3s"
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15.0)  # Longer than handshake timeout
            try:
                sock.connect(("127.0.0.1", proxy_port))

                start_time = time.time()
                try:
                    data = sock.recv(1024)
                    assert len(data) == 0, "Expected connection close"
                except socket.timeout:
                    pass

                elapsed = time.time() - start_time
                # Should timeout around 3 seconds
                assert 2.5 <= elapsed <= 5.0, \
                    f"Timeout not matching config: {elapsed}s (expected ~3s)"

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
        proxy_port = 29012
        target_port = 29013
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.send(b"IPV4_OK")
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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert success, f"Connect failed with reply code {reply}"

                sock.send(b"TEST")
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
        proxy_port = 29014
        target_port = 29015
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.send(b"IPV6_OK")
                except Exception:
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
                    conn, _ = target_socket.accept()
                    echo_handler(conn)
                except Exception:
                    pass

            thread = threading.Thread(target=accept_loop)
            thread.daemon = True
            thread.start()

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                success, reply = socks5_connect_ipv6(sock, "::1", target_port)
                assert success, f"Connect failed with reply code {reply}"

                sock.send(b"TEST")
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
        proxy_port = 29016
        target_port = 29017
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def echo_handler(conn: socket.socket) -> None:
                try:
                    data = conn.recv(1024)
                    if data:
                        conn.send(b"DOMAIN_OK")
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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                # Use localhost domain
                success, reply = socks5_connect_domain(sock, "localhost", target_port)
                assert success, f"Connect failed with reply code {reply}"

                sock.send(b"TEST")
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
        proxy_port = 29018
        target_port = 29019
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            _, target_socket = create_target_server(
                "127.0.0.1", target_port,
                lambda conn: conn.send(b"OK") or conn.close()
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert success, f"Expected success, got reply {reply}"
                assert reply == SOCKS5_REP_SUCCESS, \
                    f"Expected REP=0x00, got {reply}"

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
        proxy_port = 29020
        target_port = 29021
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            # Don't create target server - port should be unavailable

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert not success, "Connection should fail"
                assert reply == SOCKS5_REP_CONNECTION_REFUSED, \
                    f"Expected REP=0x05, got {reply}"

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
        proxy_port = 29022
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                # Port 1 - unlikely to have service, should get connection refused
                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", 1)
                # Should get some error (connection refused most likely)
                assert not success, "Connection to port 1 should fail"

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
        proxy_port = 29023
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                # Port 65535 - max valid port
                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", 65535)
                # Should get some error (connection refused most likely)
                assert not success, "Connection to port 65535 should fail"

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
        proxy_port = 29024
        target_port = 29025
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            users = [{"username": "a", "password": "test"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port,
                lambda conn: conn.send(b"OK") or conn.close()
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                success, _ = socks5_handshake_password(sock, "a", "test")
                assert success, "Authentication with 1-byte username should succeed"

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
        proxy_port = 29026
        target_port = 29027
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            users = [{"username": "test", "password": "x"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port,
                lambda conn: conn.send(b"OK") or conn.close()
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                success, _ = socks5_handshake_password(sock, "test", "x")
                assert success, "Authentication with 1-byte password should succeed"

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
        proxy_port = 29028
        target_port = 29029
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            long_username = "a" * 255
            users = [{"username": long_username, "password": "test"}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port,
                lambda conn: conn.send(b"OK") or conn.close()
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                success, _ = socks5_handshake_password(sock, long_username, "test")
                assert success, "Authentication with 255-byte username should succeed"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5DomainBoundary:
    """Tests for domain boundary values"""

    def test_domain_1_byte(self) -> None:
        """
        TC-S5-020: 1-byte domain

        Test connection to 1-byte domain (minimum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29030
        target_port = 29031
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            _, target_socket = create_target_server(
                "127.0.0.1", target_port,
                lambda conn: conn.send(b"OK") or conn.close()
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                # "a" is a valid 1-byte domain (won't resolve, but tests parsing)
                success, reply = socks5_connect_domain(sock, "a", target_port)
                # Will fail because "a" won't resolve
                assert not success, "Connection should fail"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_domain_255_bytes(self) -> None:
        """
        TC-S5-021: 255-byte domain

        Test connection to 255-byte domain (maximum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29032
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                # 255-byte domain (valid length)
                long_domain = "a" * 255
                success, reply = socks5_connect_domain(sock, long_domain, 80)
                # Will fail because domain won't resolve
                assert not success, "Connection should fail"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5MultiAddress:
    """Tests for multiple listening addresses"""

    def test_multiple_addresses(self) -> None:
        """
        TC-S5-022: Multiple listening addresses

        Test that SOCKS5 listener works on multiple addresses.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port1 = 29033
        proxy_port2 = 29034
        target_port = 29035
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # Listen on two addresses
            addresses = [
                f"0.0.0.0:{proxy_port1}",
                f"0.0.0.0:{proxy_port2}"
            ]
            config_path = create_socks5_config(
                proxy_port1, temp_dir, addresses=addresses
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port,
                lambda conn: conn.send(b"OK") or conn.close()
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port1, timeout=5.0), \
                "Proxy server failed to start on port 1"
            assert wait_for_proxy("127.0.0.1", proxy_port2, timeout=5.0), \
                "Proxy server failed to start on port 2"

            # Test first address
            sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock1.settimeout(10.0)
            try:
                sock1.connect(("127.0.0.1", proxy_port1))
                assert socks5_handshake_no_auth(sock1), "Handshake failed on port 1"
                success, _ = socks5_connect_ipv4(sock1, "127.0.0.1", target_port)
                assert success, "Connection failed on port 1"
            finally:
                sock1.close()

            # Test second address
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(10.0)
            try:
                sock2.connect(("127.0.0.1", proxy_port2))
                assert socks5_handshake_no_auth(sock2), "Handshake failed on port 2"
                success, _ = socks5_connect_ipv4(sock2, "127.0.0.1", target_port)
                assert success, "Connection failed on port 2"
            finally:
                sock2.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_address_config_error(self) -> None:
        """
        TC-S5-023: Invalid address configuration error

        Test that proxy fails to start when configuration contains
        invalid addresses. According to the actual implementation,
        invalid addresses cause a configuration error at startup.

        Note: Architecture document says "skip invalid addresses",
        but the actual implementation validates addresses at config
        time and rejects invalid configurations.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29036

        try:
            # Mix of valid and invalid addresses
            addresses = [
                "invalid-address",  # Invalid
                f"0.0.0.0:{proxy_port}",  # Valid
                "also-invalid:port",  # Invalid
            ]
            config_path = create_socks5_config(
                proxy_port, temp_dir, addresses=addresses
            )

            # Start proxy - should fail due to invalid addresses
            proxy_proc = start_proxy(config_path)

            # Wait for process to exit (should exit with error)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                # Process should exit with non-zero code
                assert exit_code != 0, \
                    f"Expected non-zero exit code for invalid config, got {exit_code}"
            except subprocess.TimeoutExpired:
                # Process didn't exit - this is unexpected
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError(
                    "Process should have exited due to invalid addresses"
                )

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5ClientDisconnect:
    """Tests for client disconnect scenarios"""

    def test_disconnect_during_handshake(self) -> None:
        """
        TC-S5-024: Client disconnect during handshake

        Test that server handles client disconnect during handshake gracefully.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29038
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Connect and disconnect immediately
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                # Send partial handshake
                sock.send(bytes([SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE]))
                # Immediately close
            finally:
                sock.close()

            # Server should still be running
            time.sleep(0.5)

            # Try another connection
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.settimeout(10.0)
            try:
                sock2.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock2), "Server should still work"
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
        proxy_port = 29039
        target_port = 29040
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            def blocking_handler(conn: socket.socket) -> None:
                try:
                    # Keep connection open
                    time.sleep(10)
                    conn.send(b"DONE")
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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"
                success, _ = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert success, "Connection failed"

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


class TestSocks5BidirectionalTransfer:
    """Tests for bidirectional data transfer"""

    def test_bidirectional_transfer(self) -> None:
        """
        TC-S5-026: Bidirectional data transfer

        Test that data can be sent in both directions through SOCKS5 tunnel.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29041
        target_port = 29042
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            received_from_client: List[bytes] = []

            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        received_from_client.append(data)
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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"
                success, _ = socks5_connect_ipv4(sock, "127.0.0.1", target_port)
                assert success, "Connection failed"

                # Send multiple messages
                messages = [b"MSG1", b"MSG2", b"MSG3"]
                for msg in messages:
                    sock.send(msg)
                    response = sock.recv(1024)
                    assert response == b"ECHO:" + msg, \
                        f"Expected 'ECHO:{msg}', got: {response}"

                # Verify all messages received
                time.sleep(0.2)
                assert len(received_from_client) == len(messages), \
                    f"Expected {len(messages)} messages, got {len(received_from_client)}"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5ConfigErrors:
    """Tests for configuration error scenarios"""

    def test_invalid_yaml_format(self) -> None:
        """
        TC-S5-027: Invalid YAML format

        Test that proxy fails to start with invalid YAML configuration.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29050

        try:
            # Create invalid YAML config
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
      addresses: [
        - "0.0.0.0:{proxy_port}"
"""
            config_path = os.path.join(temp_dir, "invalid_config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                assert exit_code != 0, \
                    "Expected non-zero exit code for invalid YAML"
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError("Process should have exited")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_missing_addresses_field(self) -> None:
        """
        TC-S5-028: Missing addresses field

        Test that proxy fails to start when addresses field is missing.
        """
        temp_dir = tempfile.mkdtemp()

        try:
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
      auth:
        users:
          - username: "test"
            password: "test"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                assert exit_code != 0, \
                    "Expected non-zero exit code for missing addresses"
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError("Process should have exited")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_empty_addresses_list(self) -> None:
        """
        TC-S5-029: Empty addresses list

        Test that proxy fails to start when addresses list is empty.
        """
        temp_dir = tempfile.mkdtemp()

        try:
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
      addresses: []
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                assert exit_code != 0, \
                    "Expected non-zero exit code for empty addresses"
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError("Process should have exited")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_password_mode_empty_users(self) -> None:
        """
        TC-S5-030: Password mode with empty users

        Test that proxy fails to start when type is password but users is empty.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29051

        try:
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
        - "0.0.0.0:{proxy_port}"
      auth:
        users: []
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                assert exit_code != 0, \
                    "Expected non-zero exit code for password mode with empty users"
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError("Process should have exited")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_auth_type(self) -> None:
        """
        TC-S5-031: Invalid auth config rejected

        Test that proxy fails to start with unknown field in auth config.
        In the new unified auth format, unknown fields should be rejected.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29052

        try:
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
        - "0.0.0.0:{proxy_port}"
      auth:
        some_unknown_field: true
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                assert exit_code != 0, \
                    "Expected non-zero exit code for invalid auth type"
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError("Process should have exited")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_invalid_handshake_timeout_format(self) -> None:
        """
        TC-S5-032: Invalid handshake timeout format

        Test that proxy fails to start with invalid handshake timeout format.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29053

        try:
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
        - "0.0.0.0:{proxy_port}"
      handshake_timeout: "invalid"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                assert exit_code != 0, \
                    "Expected non-zero exit code for invalid timeout format"
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError("Process should have exited")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5AdditionalBoundary:
    """Additional boundary value tests"""

    def test_password_255_bytes(self) -> None:
        """
        TC-S5-033: 255-byte password

        Test authentication with 255-byte password (maximum).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29054
        target_port = 29055
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            long_password = "x" * 255
            users = [{"username": "test", "password": long_password}]
            config_path = create_socks5_config(
                proxy_port, temp_dir, auth_type="password", users=users
            )

            _, target_socket = create_target_server(
                "127.0.0.1", target_port,
                lambda conn: conn.send(b"OK") or conn.close()
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                success, _ = socks5_handshake_password(sock, "test", long_password)
                assert success, "Authentication with 255-byte password should succeed"

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
        proxy_port = 29057
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                assert socks5_handshake_no_auth(sock), "Handshake failed"

                # Port 0 - invalid
                success, reply = socks5_connect_ipv4(sock, "127.0.0.1", 0)
                # Should fail
                assert not success, "Connection to port 0 should fail"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5InvalidVersion:
    """Tests for invalid SOCKS version handling"""

    def test_invalid_socks_version(self) -> None:
        """
        TC-S5-036: Invalid SOCKS version

        Test that server closes connection without response for invalid version.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29058
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Send SOCKS4 version instead of SOCKS5
                sock.send(bytes([0x04, 0x01, 0x00, 0x50]))

                # Should not receive response, connection should close
                try:
                    data = sock.recv(1024)
                    # If we get data, it should be empty (connection close)
                    assert len(data) == 0, \
                        "Should not receive response for invalid version"
                except (socket.timeout, ConnectionResetError, BrokenPipeError):
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
        proxy_port = 29059
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Send HTTP data instead of SOCKS5
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

                # Server should close connection without valid SOCKS5 response
                try:
                    data = sock.recv(1024)
                    # If we get data, it should be empty (connection close)
                    # or not be a valid SOCKS5 response
                    if len(data) > 0:
                        # Should not be SOCKS5 version 5 response
                        assert data[0] != SOCKS5_VERSION, \
                            "Should not receive valid SOCKS5 response for HTTP data"
                except (socket.timeout, ConnectionResetError, BrokenPipeError):
                    # Connection reset or timeout is acceptable
                    pass

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5HandshakeTimeoutFormat:
    """Tests for handshake timeout string format configuration"""

    def test_handshake_timeout_string_format(self) -> None:
        """
        TC-S5-038: Handshake timeout string format

        Test that handshake timeout string format (e.g., "5s") is correctly parsed.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29060
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Use 5 second timeout in string format
            config_path = create_socks5_config(
                proxy_port, temp_dir, handshake_timeout="5s"
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Don't send anything, wait for timeout
                start_time = time.time()
                try:
                    data = sock.recv(1024)
                    assert len(data) == 0, "Expected connection close"
                except socket.timeout:
                    pass

                elapsed = time.time() - start_time
                # Should timeout around 5 seconds
                assert 4.0 <= elapsed <= 8.0, \
                    f"Timeout not matching config: {elapsed}s (expected ~5s)"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_handshake_timeout_default(self) -> None:
        """
        TC-S5-039: Handshake timeout default value

        Test that default handshake timeout is 10 seconds.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29061
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # No handshake_timeout specified, should use default 10s
            config_path = create_socks5_config(proxy_port, temp_dir)

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # Don't send anything, wait for timeout
                start_time = time.time()
                try:
                    data = sock.recv(1024)
                    assert len(data) == 0, "Expected connection close"
                except socket.timeout:
                    pass

                elapsed = time.time() - start_time
                # Default should be around 10 seconds
                assert 8.0 <= elapsed <= 14.0, \
                    f"Timeout not matching default: {elapsed}s (expected ~10s)"

            finally:
                sock.close()

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSocks5TlsClientCertRejected:
    """Tests for TLS client cert rejection (SOCKS5 only supports password auth)"""

    def test_tls_client_cert_type_rejected(self) -> None:
        """
        TC-S5-040: TLS client cert auth rejected for SOCKS5

        Test that SOCKS5 listener rejects client_ca_path in auth config.
        SOCKS5 protocol only supports password authentication.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = 29062

        try:
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
        - "0.0.0.0:{proxy_port}"
      auth:
        client_ca_path: "/path/to/ca.pem"
  service: connect_tcp
"""
            config_path = os.path.join(temp_dir, "config.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proxy_proc = start_proxy(config_path)
            try:
                exit_code = proxy_proc.wait(timeout=5.0)
                assert exit_code != 0, \
                    "Expected non-zero exit code for tls_client_cert auth type in SOCKS5"
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                raise AssertionError("Process should have exited")

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)