"""
HTTP echo helper functions for integration tests.

This module provides reusable HTTP echo handlers for mock target servers
used in integration testing.
"""

import socket
from typing import Optional


def read_http_request(conn: socket.socket, timeout: float = 5.0) -> bytes:
    """Read a complete HTTP request from a socket connection.

    Reads headers until \\r\\n\\r\\n, then reads Content-Length bytes of body.
    This is more robust than a single recv() call which may not receive
    the complete request due to TCP segmentation.

    Args:
        conn: Client connection socket.
        timeout: Socket timeout in seconds.

    Returns:
        The POST body bytes, or empty bytes if no body.
    """
    conn.settimeout(timeout)
    buf = b""

    # Read until we find the end of headers
    while b"\r\n\r\n" not in buf:
        try:
            chunk = conn.recv(4096)
            if not chunk:
                return b""
            buf += chunk
        except socket.timeout:
            return b""

    # Split headers and any body data already received
    header_end = buf.index(b"\r\n\r\n") + 4
    headers_data = buf[:header_end]
    body_received = buf[header_end:]

    # Parse Content-Length from headers
    content_length = 0
    for line in headers_data.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                pass
            break

    # Read remaining body bytes if needed
    while len(body_received) < content_length:
        try:
            chunk = conn.recv(min(4096, content_length - len(body_received)))
            if not chunk:
                break
            body_received += chunk
        except socket.timeout:
            break

    return body_received[:content_length]


def http_echo_handler(conn: socket.socket) -> None:
    """HTTP echo handler that properly parses HTTP requests and echoes POST body.

    This handler reads the complete HTTP request (headers + body) using
    Content-Length, then sends back a valid HTTP 200 response with the
    POST body as the response body.

    Args:
        conn: Client connection socket.
    """
    try:
        body = read_http_request(conn)

        # Send HTTP response with the body
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n"
        ) + body
        conn.sendall(response)
    except Exception:
        pass
    finally:
        conn.close()
