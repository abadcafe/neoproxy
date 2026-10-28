"""Public process contracts for flat configuration and QUIC transport deadlines."""

import asyncio
import subprocess
import time
from pathlib import Path
from typing import override

import pytest
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

from tests.fixtures.binary import NEOPROXY_BINARY
from tests.fixtures.configuration import ConfigDict, dict_to_yaml
from tests.fixtures.matrix_model import CertificateFiles
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process


def _errors(directory: Path) -> str:
    return "\n".join(
        line
        for log in (directory / "logs").glob("neoproxy.log*")
        for line in log.read_text().splitlines()
        if " ERROR " in line
    )


def _configuration(
    port: int, certs: CertificateFiles, fields: ConfigDict
) -> ConfigDict:
    return {
        "server_threads": 1,
        "plugins": {"echo": {}},
        "listeners": [
            {
                "name": "main",
                "kind": "http3",
                "addresses": [f"127.0.0.1:{port}"],
                **fields,
            }
        ],
        "services": [{"name": "main", "kind": "echo.echo"}],
        "servers": [
            {
                "name": "main",
                "listeners": ["main"],
                "service": "main",
                "certificates": [
                    {"cert_path": certs.server_cert, "key_path": certs.server_key}
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    "fields",
    [
        {"quic_connection_max_concurrent_bidi_streams": 0},
        {"quic_connection_max_concurrent_bidi_streams": (1 << 60) + 1},
        {"quic_connection_handshake_timeout": "0s"},
        {"quic_connection_keep_alive_interval": "0s"},
        {
            "quic_connection_keep_alive_interval": "6s",
            "quic_connection_idle_timeout": "5s",
        },
        {"quic_stream_receive_window": "0B"},
        {"quic_stream_receive_window": "4611686018427387904B"},
        {"tcp_keep_alive_time": "1s"},
        {"misspelled_timeout": "1s"},
    ],
)
def test_flat_http3_configuration_rejects_invalid_transport_fields(
    tmp_path: Path, matrix_certificates: CertificateFiles, fields: ConfigDict
) -> None:
    path = tmp_path / "invalid.yaml"
    _ = path.write_text(
        dict_to_yaml(_configuration(get_unique_port(), matrix_certificates, fields))
    )
    result = subprocess.run(
        [NEOPROXY_BINARY, "-c", str(path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode != 0
    output = result.stdout + result.stderr + _errors(tmp_path)
    assert any(field in output for field in fields), output


class UnresponsiveClient(QuicConnectionProtocol):
    @override
    def datagram_received(
        self, data: bytes, addr: tuple[str, int] | tuple[str, int, int, int]
    ) -> None:
        # Public asyncio transport callback: deliberately never process the
        # server flight, so the peer cannot finish its TLS handshake.
        pass


@pytest.mark.asyncio
async def test_quic_connection_handshake_timeout_bounds_incomplete_handshake(
    tmp_path: Path, matrix_certificates: CertificateFiles
) -> None:
    port = get_unique_port()
    path = tmp_path / "proxy.yaml"
    _ = path.write_text(
        dict_to_yaml(
            _configuration(
                port,
                matrix_certificates,
                {
                    "quic_connection_handshake_timeout": "100ms",
                    "quic_connection_idle_timeout": "10s",
                    "quic_connection_max_concurrent_bidi_streams": 10001,
                    "quic_stream_receive_window": "4KiB",
                },
            )
        )
    )
    process = start_proxy(str(path))
    try:
        assert process.wait_ready()
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        configuration.idle_timeout = 1
        async with connect(
            "127.0.0.1",
            port,
            configuration=configuration,
            create_protocol=UnresponsiveClient,
            wait_connected=False,
        ) as protocol:
            protocol.transmit()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                logs = "".join(
                    log.read_text() for log in (tmp_path / "logs").glob("neoproxy.log*")
                )
                if "QUIC connection handshake timed out" in logs:
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail(
                    "incomplete QUIC handshake outlived its configured deadline"
                )
        assert process.poll() is None
    finally:
        terminate_process(process)


@pytest.mark.asyncio
async def test_quic_keepalive_preserves_idle_connection_and_small_stream_window(
    tmp_path: Path, matrix_certificates: CertificateFiles
) -> None:
    from tests.fixtures.http3_client import H3Client

    port = get_unique_port()
    path = tmp_path / "proxy.yaml"
    _ = path.write_text(
        dict_to_yaml(
            _configuration(
                port,
                matrix_certificates,
                {
                    "quic_connection_keep_alive_interval": "100ms",
                    "quic_connection_idle_timeout": "500ms",
                    "quic_stream_receive_window": "4KiB",
                },
            )
        )
    )
    process = start_proxy(str(path))
    client = H3Client("127.0.0.1", port, ca_path=matrix_certificates.ca)
    try:
        assert process.wait_ready()
        assert await client.connect(), client.connection_error
        first = await client.send_request("GET", "/")
        assert first.status_code == 200
        await asyncio.sleep(1.2)
        payload = b"window-test\x00\xff" * 4096
        response = await asyncio.wait_for(
            client.send_request("POST", "/", body=payload), timeout=5
        )
        assert response.status_code == 200
        assert response.body == payload
    finally:
        await client.close()
        terminate_process(process)


@pytest.mark.parametrize("location", ["service", "layer"])
def test_flat_plugin_configuration_rejects_unknown_fields(
    tmp_path: Path, matrix_certificates: CertificateFiles, location: str
) -> None:
    config = _configuration(get_unique_port(), matrix_certificates, {})
    service: ConfigDict = {"name": "main", "kind": "echo.echo"}
    if location == "service":
        service["misspelled_option"] = True
    else:
        config["plugins"] = {"echo": {}, "auth": {}}
        service["layers"] = [
            {
                "kind": "auth.basic_auth",
                "users": [{"username": "u", "password": "p"}],
                "misspelled_option": True,
            }
        ]
    config["services"] = [service]
    path = tmp_path / "invalid.yaml"
    _ = path.write_text(dict_to_yaml(config))
    result = subprocess.run(
        [NEOPROXY_BINARY, "-c", str(path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode != 0
    assert "misspelled_option" in result.stdout + result.stderr + _errors(tmp_path)
