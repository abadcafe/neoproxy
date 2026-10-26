"""module: h3_tunnel; responsibility: probe H3 CONNECT tunnels.
Public operations: perform_h3_connect_test, perform_h3_connect_test_full,
perform_h3_tunnel_data_transfer, H3ConnectResult, H3TunnelResult.
Data entities: H3ConnectResult, H3TunnelResult. Tests: tunnel process contracts.
"""

import asyncio
from dataclasses import dataclass, field

from .http3_client import H3Client


@dataclass
class H3ConnectResult:
    success: bool
    status_code: int
    message: str
    stream_id: int = 0
    response_headers: dict[str, str] = field(default_factory=dict[str, str])


@dataclass
class H3TunnelResult:
    success: bool
    status_code: int
    data_sent: int
    data_received: int
    message: str
    response_data: bytes = b""


async def perform_h3_connect_test_full(
    host: str,
    port: int,
    target_host: str,
    target_port: int,
    ca_path: str | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 10.0,
    server_hostname: str | None = None,
) -> H3ConnectResult:
    client = H3Client(host, port, ca_path=ca_path, server_hostname=server_hostname)
    try:
        async with asyncio.timeout(timeout):
            if not await client.connect():
                return H3ConnectResult(False, 0, client.connection_error)
            response = await client.send_connect_request(
                target_host, target_port, username, password
            )
            return H3ConnectResult(
                200 <= response.status_code < 300,
                response.status_code,
                f"Status: {response.status_code}",
                response.stream_id,
                response.headers,
            )
    except TimeoutError:
        return H3ConnectResult(False, 0, "Request timeout")
    finally:
        await client.close()


async def perform_h3_connect_test(
    host: str,
    port: int,
    target_host: str,
    target_port: int,
    ca_path: str | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 10.0,
) -> tuple[bool, int, str]:
    result = await perform_h3_connect_test_full(
        host, port, target_host, target_port, ca_path, username, password, timeout
    )
    return result.success, result.status_code, result.message


async def perform_h3_tunnel_data_transfer(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    ca_path: str | None = None,
    client_cert_path: str | None = None,
    client_key_path: str | None = None,
    test_data: bytes = b"HELLO_FROM_H3_CLIENT",
    timeout: float = 15.0,
    server_hostname: str | None = None,
) -> H3TunnelResult:
    client = H3Client(
        proxy_host,
        proxy_port,
        ca_path=ca_path,
        cert_path=client_cert_path,
        key_path=client_key_path,
        server_hostname=server_hostname,
    )
    try:
        async with asyncio.timeout(timeout):
            if not await client.connect():
                return H3TunnelResult(False, 0, 0, 0, client.connection_error)
            response = await client.send_connect_request(target_host, target_port)
            if not 200 <= response.status_code < 300:
                return H3TunnelResult(
                    False, response.status_code, 0, 0, "CONNECT failed"
                )
            received = await client.transfer_tunnel(response.stream_id, test_data)
            return H3TunnelResult(
                received is not None,
                response.status_code,
                len(test_data),
                len(received) if received is not None else 0,
                "stream completed" if received is not None else "stream failed",
                received if received is not None else b"",
            )
    except TimeoutError:
        return H3TunnelResult(False, 0, 0, 0, "Request timeout")
    finally:
        await client.close()
