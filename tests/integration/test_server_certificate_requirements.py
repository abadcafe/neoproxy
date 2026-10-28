"""Every server bound to HTTPS/H3 needs its own configured identity."""

import socket
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.configuration import ConfigDict, StringMap, dict_to_yaml
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import start_proxy, terminate_process


@pytest.mark.parametrize("kind", ["https", "http3"])
@pytest.mark.parametrize("named", [False, True])
@pytest.mark.parametrize("scenario", ["sole", "shared", "mixed"])
@pytest.mark.parametrize("explicit_empty", [False, True])
def test_missing_server_certificate_fails_before_workers_or_readiness(
    tmp_path: Path,
    shared_test_certs: StringMap,
    kind: Literal["https", "http3"],
    named: bool,
    scenario: Literal["sole", "shared", "mixed"],
    explicit_empty: bool,
) -> None:
    port = get_unique_port()
    plain_port = get_unique_port()
    missing: ConfigDict = {
        "name": "missing_identity",
        "hostnames": ["missing.test"] if named else [],
        "listeners": ["plain", "secure"] if scenario == "mixed" else ["secure"],
        "service": "echo",
    }
    if explicit_empty:
        missing["certificates"] = []
    servers: list[ConfigDict] = [missing]
    if scenario == "shared":
        servers.append(
            {
                "name": "valid_identity",
                "hostnames": ["localhost"],
                "listeners": ["secure"],
                "service": "echo",
                "certificates": [
                    {
                        "cert_path": shared_test_certs["cert_path"],
                        "key_path": shared_test_certs["key_path"],
                    }
                ],
            }
        )
    config: ConfigDict = {
        "server_threads": 2,
        "plugins": {"echo": {}},
        "services": [{"name": "echo", "kind": "echo.echo"}],
        "listeners": [
            {"name": "plain", "kind": "http", "addresses": [f"127.0.0.1:{plain_port}"]},
            {"name": "secure", "kind": kind, "addresses": [f"127.0.0.1:{port}"]},
        ],
        "servers": [*servers],
    }
    path = tmp_path / "invalid.yaml"
    _ = path.write_text(dict_to_yaml(config))
    process = start_proxy(str(path))
    try:
        assert not process.wait_ready()
        _, stderr = process.communicate(timeout=5)
        assert process.returncode == 1
        for expected in [
            b"servers[0].certificates",
            b"missing_identity",
            b"secure",
            kind.encode(),
        ]:
            assert expected in stderr, stderr
        # Config rejection occurs before worker logging/listener creation.
        assert not (tmp_path / "logs").exists()
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM if kind == "https" else socket.SOCK_DGRAM
        ) as probe:
            probe.bind(("127.0.0.1", port))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", plain_port))
    finally:
        terminate_process(process)
