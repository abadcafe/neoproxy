"""module: h3_connection; responsibility: probe H3 TLS authentication.
Public operations: perform_h3_connection_test, perform_h3_tls_client_cert_test.
Data entities: none. Tests: TLS process contracts.
"""

import asyncio

from .http3_client import H3Client


async def _probe(client: H3Client, timeout: float) -> tuple[bool, int, str]:
    try:
        async with asyncio.timeout(timeout):
            if not await client.connect():
                return False, 0, client.connection_error
            response = await client.send_request("GET", "/")
            return (
                response.status_code != 0,
                response.status_code,
                response.body.decode(errors="replace"),
            )
    except TimeoutError:
        return False, 0, "Connection timeout"
    finally:
        await client.close()


async def perform_h3_connection_test(
    host: str,
    port: int,
    ca_path: str | None = None,
    timeout: float = 10.0,
    server_hostname: str | None = None,
) -> tuple[bool, int, str]:
    return await _probe(
        H3Client(host, port, ca_path=ca_path, server_hostname=server_hostname), timeout
    )


async def perform_h3_tls_client_cert_test(
    proxy_host: str,
    proxy_port: int,
    ca_path: str,
    client_cert_path: str,
    client_key_path: str,
    timeout: float = 10.0,
    server_hostname: str | None = None,
) -> tuple[bool, int, str]:
    return await _probe(
        H3Client(
            proxy_host,
            proxy_port,
            ca_path=ca_path,
            cert_path=client_cert_path,
            key_path=client_key_path,
            server_hostname=server_hostname,
        ),
        timeout,
    )
