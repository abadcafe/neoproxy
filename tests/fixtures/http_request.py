"""module: http_request; responsibility: http request fixtures.
Public operations: establish_connect_tunnel, send_raw_request.
Tests: sibling module tests and public fixture consumers.
"""

import socket


def establish_connect_tunnel(
    proxy_host: str, proxy_port: int, target_host: str, target_port: int
) -> socket.socket | None:
    """
    Establish a CONNECT tunnel through the proxy.

    Args:
        proxy_host: Proxy server host
        proxy_port: Proxy server port
        target_host: Target server host
        target_port: Target server port

    Returns:
        socket.socket | None: Socket if tunnel established, None otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((proxy_host, proxy_port))

        connect_request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost:"
            + f" {target_host}:{target_port}\r\n\r\n"
        ).encode()
        sock.sendall(connect_request)

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk

        if b"200" in response:
            return sock
        else:
            sock.close()
            return None
    except OSError:
        sock.close()
        return None


def send_raw_request(
    host: str, port: int, request: bytes, timeout: float = 5.0
) -> bytes:
    """
    Send raw HTTP request and read response.

    Args:
        host: Target host
        port: Target port
        request: Raw HTTP request bytes
        timeout: Socket timeout in seconds

    Returns:
        bytes: Response data
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(request)

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            # If we got a complete HTTP response header, stop
            if b"\r\n\r\n" in response:
                break
        return response
    finally:
        sock.close()
