"""module: udp_sockets; responsibility: observe process-owned UDP bindings.
Public operations: bound_socket_count. Data entities: none.
Tests: HTTP/3 worker binding and shutdown process tests.
"""

import psutil

from tests.fixtures.proxy_process import BytesProcess


def bound_socket_count(process: BytesProcess, port: int) -> int:
    try:
        connections = psutil.Process(process.pid).net_connections(kind="udp")
    except psutil.NoSuchProcess:
        return 0
    return len(
        {
            connection.fd
            for connection in connections
            if connection.laddr and connection.laddr.port == port
        }
    )
