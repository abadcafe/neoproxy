"""module: h3_request; responsibility: perform isolated H3 request scenarios.
Public operations: perform_h3_request_test, perform_h3_request_with_custom_authority.
Data entities: none. Tests: h3_request_tests.py and request process contracts.
"""

import asyncio

from .http3_client import H3Client, H3Response


async def perform_h3_request_test(
    host: str,
    port: int,
    method: str,
    path: str,
    ca_path: str | None = None,
    headers: list[tuple[str, str]] | None = None,
    body: bytes | None = None,
    timeout: float = 10.0,
    server_hostname: str | None = None,
) -> H3Response:
    client = H3Client(host, port, ca_path=ca_path, server_hostname=server_hostname)
    try:
        async with asyncio.timeout(timeout):
            if not await client.connect():
                return H3Response(0, {}, client.connection_error.encode(), 0)
            return await client.send_request(method, path, headers, body)
    except TimeoutError:
        return H3Response(0, {}, b"Timeout", 0)
    finally:
        await client.close()


async def perform_h3_request_with_custom_authority(
    host: str,
    port: int,
    custom_authority: str,
    path: str = "/",
    method: str = "GET",
    ca_path: str | None = None,
    additional_headers: list[tuple[str, str]] | None = None,
    timeout: float = 10.0,
    server_hostname: str | None = None,
) -> H3Response:
    client = H3Client(host, port, ca_path=ca_path, server_hostname=server_hostname)
    try:
        async with asyncio.timeout(timeout):
            if not await client.connect():
                return H3Response(0, {}, client.connection_error.encode(), 0)
            return await client.send_request(
                method, path, additional_headers, authority=custom_authority
            )
    except TimeoutError:
        return H3Response(0, {}, b"Timeout", 0)
    finally:
        await client.close()
