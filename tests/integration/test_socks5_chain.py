"""curl contract for HTTP -> SOCKS5 -> direct with real NeoProxy listeners."""

from pathlib import Path

import pytest
from pydantic import BaseModel, TypeAdapter

from tests.fixtures.configuration import ConfigDict, JsonValue
from tests.fixtures.http_echo import http_echo_handler
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.ports import get_unique_port
from tests.fixtures.socks5_upstream import configuration, curl_tunnel
from tests.fixtures.tcp_peer import TargetServerFactory


class AccessEntry(BaseModel):
    extensions: dict[str, JsonValue]


@pytest.mark.asyncio
@pytest.mark.parametrize("authenticated", [False, True])
async def test_real_socks_chain_and_selected_protocol(
    tmp_path: Path, target_server: TargetServerFactory, authenticated: bool
) -> None:
    origin = get_unique_port()
    _ = target_server(origin, http_echo_handler)
    user: ConfigDict = {"username": "alice", "password": "secret"}
    next_config = configuration([])
    next_config["listeners"] = [{"name": "main", "kind": "socks5"}]
    if authenticated:
        plugins = TypeAdapter(ConfigDict).validate_python(next_config["plugins"])
        plugins["auth"] = {}
        next_config["plugins"] = plugins
        services = TypeAdapter(list[ConfigDict]).validate_python(
            next_config["services"]
        )
        services[0]["layers"] = [{"kind": "auth.basic_auth", "args": {"users": [user]}}]
        next_config["services"] = list(services)
    entry_dir = tmp_path / "entry"
    with running_proxy(tmp_path / "next", next_config) as next_proxy:
        entry_config = configuration(
            [{"address": f"127.0.0.1:{next_proxy.port}"}],
            user if authenticated else None,
        )
        plugins = TypeAdapter(ConfigDict).validate_python(entry_config["plugins"])
        plugins["access_log"] = {
            "writers": [
                {
                    "path_prefix": "logs/access",
                    "format": "json",
                    "flush_interval": "10ms",
                }
            ]
        }
        entry_config["plugins"] = plugins
        services = TypeAdapter(list[ConfigDict]).validate_python(
            entry_config["services"]
        )
        services[0]["layers"] = [
            {
                "kind": "access_log.file",
                "args": {
                    "writer": "logs/access",
                    "context_fields": ["upstream.protocol"],
                },
            }
        ]
        entry_config["services"] = list(services)
        with running_proxy(entry_dir, entry_config) as proxy:
            assert await curl_tunnel(proxy.port, f"127.0.0.1:{origin}") == (200, b"")
    entries = [
        AccessEntry.model_validate_json(line)
        for path in (entry_dir / "logs").glob("access*")
        for line in path.read_text().splitlines()
    ]
    assert len(entries) == 1
    assert entries[0].extensions["upstream.protocol"] == "socks5"
