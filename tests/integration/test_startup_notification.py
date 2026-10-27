"""Readiness belongs to the complete worker/listener startup transaction."""

import socket
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.configuration import StringMap
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process


@pytest.mark.parametrize("workers", [1, 4])
@pytest.mark.parametrize("transport", ["tcp", "udp"])
def test_later_listener_bind_failure_never_notifies_readiness(
    tmp_path: Path,
    shared_test_certs: StringMap,
    workers: int,
    transport: Literal["tcp", "udp"],
) -> None:
    healthy, occupied = get_unique_port(), get_unique_port()
    kind = "http" if transport == "tcp" else "http3"
    tls = (
        ""
        if transport == "tcp"
        else f"""  tls:
    certificates:
    - cert_path: {shared_test_certs["cert_path"]}
      key_path: {shared_test_certs["key_path"]}
"""
    )
    config = tmp_path / "proxy.yaml"
    _ = config.write_text(f"""server_threads: {workers}
plugins:
  echo: {{}}
services:
- name: echo
  kind: echo.echo
listeners:
- name: healthy
  kind: http
  addresses: ["127.0.0.1:{healthy}"]
- name: occupied
  kind: {kind}
  addresses: ["127.0.0.1:{occupied}"]
servers:
- name: healthy
  listeners: [healthy]
  service: echo
- name: occupied
  listeners: [occupied]
  service: echo
{tls}""")
    with socket.socket(
        socket.AF_INET, socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
    ) as owner:
        owner.bind(("127.0.0.1", occupied))
        if transport == "tcp":
            owner.listen()
        process = start_proxy(str(config))
        try:
            assert not process.wait_ready(timeout=3)
            assert process.wait(timeout=3) == 2
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as released:
                released.bind(("127.0.0.1", healthy))
        finally:
            terminate_process(process)
