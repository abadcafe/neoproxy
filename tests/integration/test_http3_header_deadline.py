"""Process contract: one stalled H3 header block cannot retain a request slot."""

import asyncio
import ssl
from pathlib import Path

from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamReset

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_lifecycle import LifecycleClient
from tests.fixtures.ports import get_unique_port, wait_for_udp_port_bound
from tests.fixtures.proxy_process import managed_processes


async def verify_header_deadline(port: int) -> None:
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = ssl.CERT_NONE
    config.server_name = "localhost"
    async with connect(
        "127.0.0.1", port, configuration=config, create_protocol=LifecycleClient
    ) as protocol:
        assert isinstance(protocol, LifecycleClient)
        stalled = protocol.incomplete_request()
        async with asyncio.timeout(1):
            event = await protocol.next_event(stalled)
            assert isinstance(event, StreamReset), event
        healthy = protocol.request(b"POST", b"localhost")
        protocol.http.send_data(healthy, b"alive", end_stream=True)
        protocol.transmit()
        await protocol.read_data(healthy, b"alive")
        _ = await protocol.read_end(healthy)


def test_http3_header_deadline_resets_only_stalled_request(tmp_path: Path) -> None:
    cert, key, _, _ = generate_test_certificates(str(tmp_path))
    port = get_unique_port()
    config = tmp_path / "server.yaml"
    _ = config.write_text(f"""server_threads: 1
plugins:
  echo: {{}}
listeners:
- name: main
  kind: http3
  addresses: ["127.0.0.1:{port}"]
  args:
    header_read_timeout: 100ms
services:
- name: echo
  kind: echo.echo
servers:
- name: main
  service: echo
  listeners: [main]
  tls:
    certificates:
    - cert_path: {cert}
      key_path: {key}
""")
    with managed_processes() as start:
        process = start(str(config))
        assert wait_for_udp_port_bound("127.0.0.1", port, timeout=3, proc=process)
        asyncio.run(verify_header_deadline(port))
