"""module: h3_connection; responsibility: probe H3 TLS authentication.
Public operations: perform_h3_connection_test.
Data entities: none. Tests: h3_connection_tests.py, TLS process contracts.
"""

import asyncio

from .http3_client import H3Client


async def _probe(client: H3Client, timeout: float) -> tuple[bool, int, str]:
    try:
        async with asyncio.timeout(timeout):
            if not await client.connect():
                return False, 0, client.connection_error
            # Stop at the authenticated proxy; upstream reachability is a
            # separate contract from TLS and certificate authentication.
            response = await client.send_request(
                "OPTIONS", "/", headers=[("max-forwards", "0")]
            )
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
