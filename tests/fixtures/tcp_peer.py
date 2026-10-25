"""module: tcp_peer; responsibility: tcp peer fixtures.
Public operations: create_target_server, echo_handler, one_shot_echo_handler,
blocking_handler, http_echo_handler, managed_target_servers, send_ok_and_close.
Data entities: TargetHandler, TargetServerFactory.
Tests: tcp_peer_tests.py and public fixture consumers.
"""

import socket
import threading
import time
from collections.abc import Callable, Generator
from contextlib import ExitStack, contextmanager

type TargetHandler = Callable[[socket.socket], None]
type TargetServerFactory = Callable[[int, TargetHandler], socket.socket]


def send_ok_and_close(conn: socket.socket) -> None:
    conn.sendall(b"OK")
    conn.close()


@contextmanager
def managed_target_servers() -> Generator[TargetServerFactory, None, None]:
    """Own all listening sockets created by a target-server factory."""
    with ExitStack() as resources:

        def start(port: int, handler: TargetHandler) -> socket.socket:
            _, listener = create_target_server("127.0.0.1", port, handler)
            return resources.enter_context(listener)

        yield start


def create_target_server(
    host: str, port: int, handler: TargetHandler
) -> tuple[threading.Thread, socket.socket]:
    """
    Create a mock target server for testing.

    Args:
        host: Listen address
        port: Listen port
        handler: Connection handler function

    Returns:
        tuple[threading.Thread, socket.socket]: Server thread and socket
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1024)

    running = threading.Event()
    running.set()

    def server_loop() -> None:
        while running.is_set():
            try:
                server_socket.settimeout(0.5)
                conn = server_socket.accept()[0]
                thread = threading.Thread(target=handler, args=(conn,))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=server_loop)
    thread.daemon = True
    thread.start()

    return thread, server_socket


def echo_handler(conn: socket.socket) -> None:
    """
    Echo handler that sends back received data with prefix.

    Args:
        conn: Client connection socket
    """
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"ECHO:" + data)
    except OSError:
        pass
    finally:
        conn.close()


def one_shot_echo_handler(conn: socket.socket) -> None:
    """
    Echo handler that closes after one response.

    Use this instead of echo_handler when:
    - Testing with curl --http0.9 (which waits for connection close)
    - You only need to verify data transmission, not persistent connections

    Args:
        conn: Client connection socket
    """
    try:
        data = conn.recv(1024)
        if data:
            conn.sendall(b"ECHO:" + data)
    except OSError:
        pass
    finally:
        conn.close()


def blocking_handler(conn: socket.socket, block_time: float = 60.0) -> None:
    """
    Blocking handler that keeps connection open for specified time.

    Args:
        conn: Client connection socket
        block_time: Time to block in seconds
    """
    try:
        time.sleep(block_time)
    finally:
        conn.close()


def http_echo_handler(conn: socket.socket) -> None:
    """
    HTTP echo handler that returns a valid HTTP response.

    Args:
        conn: Client connection socket
    """
    try:
        data = conn.recv(1024)
        if data:
            http_response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length:"
                + b" 2\r\n\r\nOK"
            )
            conn.sendall(http_response)
    except OSError:
        pass
    finally:
        conn.close()
