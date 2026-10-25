"""Verify independent HTTP/3 worker sockets through Linux and QUIC interfaces."""

import asyncio
import socket
import time
from pathlib import Path

import pytest

from tests.fixtures.configuration import StringMap
from tests.fixtures.http3_client import H3Client
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process
from tests.fixtures.udp_sockets import bound_socket_count


async def _exchange(host: str, port: int, ca: str, number: int) -> None:
    client = H3Client(host, port, ca_path=ca)
    try:
        assert await client.connect()
        for turn in range(2):
            payload = f"connection-{number}-turn-{turn}".encode() + b"\x00\xff"
            response = await client.send_request("POST", "/", body=payload)
            assert response.status_code == 200
            assert response.body == payload
    finally:
        await client.close()


@pytest.mark.parametrize("workers", [1, 2, 4])
@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_http3_workers_bind_independent_sockets_and_serve_requests(
    tmp_path: Path, shared_test_certs: StringMap, workers: int, host: str
) -> None:
    port = get_unique_port()
    address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    config = tmp_path / "server.yaml"
    _ = config.write_text(f"""server_threads: {workers}
plugins:
  echo: {{}}
listeners:
- name: main
  kind: http3
  addresses: ["{address}"]
services:
- name: echo
  kind: echo.echo
servers:
- name: echo
  service: echo
  listeners: [main]
  tls:
    certificates:
    - cert_path: {shared_test_certs["cert_path"]}
      key_path: {shared_test_certs["key_path"]}
""")
    process = start_proxy(str(config))
    try:
        deadline = time.monotonic() + 3
        count = 0
        while time.monotonic() < deadline:
            assert process.poll() is None
            count = bound_socket_count(process, port)
            if count == workers:
                break
            time.sleep(0.02)
        assert count == workers, f"expected {workers} UDP sockets, got {count}"

        async def requests() -> None:
            async with asyncio.timeout(8):
                async with asyncio.TaskGroup() as group:
                    for number in range(16):
                        _ = group.create_task(
                            _exchange(host, port, shared_test_certs["ca_path"], number)
                        )

        asyncio.run(requests())
        assert bound_socket_count(process, port) == workers
        process.terminate()
        assert process.wait(timeout=5) == 0
        # Exclusive binding proves all worker sockets released the port.
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.bind((host, port))
    finally:
        terminate_process(process, force=True)
