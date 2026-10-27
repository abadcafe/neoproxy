"""Access-log contracts for the selected upstream proxy protocol."""

import socket
import time
from http.client import HTTPConnection
from pathlib import Path

from pydantic import BaseModel, TypeAdapter

from tests.fixtures.access_log_configuration import enable_access_log
from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict, JsonValue, dict_to_yaml
from tests.fixtures.forward_scenario import ForwardNode, write_forward_node
from tests.fixtures.http_echo import http_echo_handler
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import managed_processes
from tests.fixtures.tcp_peer import TargetServerFactory


class AccessEntry(BaseModel):
    extensions: dict[str, JsonValue]


def entries(directory: Path) -> list[AccessEntry]:
    result: list[AccessEntry] = []
    for path in (directory / "logs").glob("access*"):
        text = path.read_text()
        if text and not text.endswith("\n"):
            return []
        result.extend(
            AccessEntry.model_validate_json(line) for line in text.splitlines()
        )
    return result


def test_failover_records_the_last_selected_protocol(
    tmp_path: Path, target_server: TargetServerFactory
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["proxy.test", "127.0.0.1"]
    )
    origin_port, next_port, entry_port = (get_unique_port() for _ in range(3))
    _ = target_server(origin_port, http_echo_handler)
    next_path = write_forward_node(
        tmp_path / "next", ForwardNode(port=next_port, certificate=cert, key=key)
    )
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        closed_port = TypeAdapter(tuple[str, int]).validate_python(
            closed.getsockname()
        )[1]
    entry_dir = tmp_path / "entry"
    entry_dir.mkdir()
    config: ConfigDict = {
        "server_threads": 1,
        "plugins": {
            "upstream": {
                "certificates": {"server_ca_path": ca},
                "upstreams": [
                    {
                        "name": "route",
                        "addresses": [
                            {
                                "address": f"127.0.0.1:{closed_port}",
                                "address_protocol": "https",
                            },
                            {
                                "address": f"127.0.0.1:{next_port}",
                                "address_protocol": "http",
                            },
                        ],
                    }
                ],
            }
        },
        "listeners": [
            {"name": "main", "kind": "http", "addresses": [f"127.0.0.1:{entry_port}"]}
        ],
        "services": [
            {
                "name": "forward",
                "kind": "upstream.upstream",
                "args": {"upstream": "route"},
            }
        ],
        "servers": [{"name": "forward", "listeners": ["main"], "service": "forward"}],
    }
    path = entry_dir / "proxy.yaml"
    _ = path.write_text(dict_to_yaml(config))
    enable_access_log(str(path), ["upstream.protocol"])
    with managed_processes() as start:
        next_process = start(next_path)
        assert next_process.wait_ready(timeout=3)
        proxy = start(str(path))
        assert proxy.wait_ready(timeout=3)
        client = HTTPConnection("127.0.0.1", entry_port, timeout=5)
        try:
            client.request("GET", f"http://127.0.0.1:{origin_port}/")
            response = client.getresponse()
            assert response.status == 200
            _ = response.read()
        finally:
            client.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not entries(entry_dir):
            time.sleep(0.01)
        assert entries(entry_dir)[0].extensions["upstream.protocol"] == "http"


def test_failed_connection_records_selected_protocol(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    entry_port = get_unique_port()
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        closed_port = TypeAdapter(tuple[str, int]).validate_python(
            closed.getsockname()
        )[1]
    config = write_forward_node(
        tmp_path,
        ForwardNode(
            port=entry_port,
            certificate=cert,
            key=key,
            ca=ca,
            upstream_port=closed_port,
            upstream_kind="https",
        ),
    )
    enable_access_log(config, ["upstream.protocol"])
    with managed_processes() as start:
        proxy = start(config)
        assert proxy.wait_ready(timeout=3)
        client = HTTPConnection("127.0.0.1", entry_port, timeout=5)
        try:
            client.request("GET", "http://127.0.0.1:8000/")
            response = client.getresponse()
            assert response.status == 502
            _ = response.read()
        finally:
            client.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not entries(tmp_path):
            time.sleep(0.01)
        assert entries(tmp_path)[0].extensions["upstream.protocol"] == "https"
