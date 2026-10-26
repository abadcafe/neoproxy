"""HTTP/3 response framing observed on a real QUIC stream."""

import asyncio
import ssl
from pathlib import Path

from aioquic.asyncio.client import connect
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.h3_lifecycle import LifecycleClient
from tests.fixtures.ports import get_unique_port, wait_for_udp_port_bound
from tests.fixtures.proxy_process import managed_processes


async def head_response(port: int) -> None:
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = ssl.CERT_NONE
    config.server_name = "localhost"
    async with connect(
        "127.0.0.1", port, configuration=config, create_protocol=LifecycleClient
    ) as protocol:
        assert isinstance(protocol, LifecycleClient)
        stream = protocol.request(b"HEAD", b"localhost")
        protocol.http.send_data(stream, b"request payload", end_stream=True)
        protocol.transmit()
        status = 0
        body = bytearray()
        async with asyncio.timeout(3):
            while True:
                event = await protocol.next_event(stream)
                assert not isinstance(event, (StreamReset, ConnectionTerminated)), event
                if isinstance(event, HeadersReceived):
                    status = int(dict(event.headers).get(b":status", b"0"))
                elif isinstance(event, DataReceived):
                    body.extend(event.data)
                if isinstance(event, (HeadersReceived, DataReceived)):
                    if event.stream_ended:
                        break
                elif isinstance(event, StreamDataReceived) and event.end_stream:
                    break
        assert status == 200
        assert not body, "HEAD response carried a DATA payload"


def test_http3_head_response_finishes_without_payload(tmp_path: Path) -> None:
    cert, key, _, _ = generate_test_certificates(str(tmp_path))
    port = get_unique_port()
    path = tmp_path / "server.yaml"
    _ = path.write_text(f"""server_threads: 1
plugins:
  echo: {{}}
listeners:
- name: main
  kind: http3
  addresses: ["127.0.0.1:{port}"]
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
        process = start(str(path))
        assert wait_for_udp_port_bound("127.0.0.1", port, timeout=3, proc=process)
        asyncio.run(head_response(port))
