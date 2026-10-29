"""HTTP and SOCKS5 CONNECT share hostname routing and selected-service auth."""

import asyncio
import subprocess
from pathlib import Path
from typing import Literal

import pytest

from tests.fixtures.configuration import ConfigDict, JsonValue
from tests.fixtures.curl import get_curl_env_without_no_proxy
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.socks5_upstream import configuration, socks_peer


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["http", "socks5"])
@pytest.mark.parametrize("default", [True, False])
@pytest.mark.parametrize(
    ("host", "route"),
    [
        ("api.example.test", "exact"),
        ("API.EXAMPLE.TEST", "exact"),
        ("other.example.test", "wildcard"),
        ("unmatched.test", "fallback"),
        ("127.0.0.1", "ipv4"),
        ("[::1]", "ipv6"),
    ],
)
async def test_connect_routes_then_authenticates_selected_service(
    tmp_path: Path,
    protocol: Literal["http", "socks5"],
    default: bool,
    host: str,
    route: str,
) -> None:
    async with socks_peer() as peer:
        config = configuration([{"address": f"127.0.0.1:{peer.port}"}])
        plugins = config["plugins"]
        assert isinstance(plugins, dict)
        plugins["auth"] = {}
        config["listeners"] = [{"name": "main", "kind": protocol}]
        services: list[JsonValue] = []
        servers: list[JsonValue] = []
        for name, names in [
            ("fallback", []),
            ("wildcard", ["*.example.test"]),
            ("exact", ["api.example.test"]),
            ("ipv4", ["127.0.0.1"]),
            ("ipv6", ["[::1]"]),
        ]:
            if name == "fallback" and not default:
                continue
            service: ConfigDict = {
                "name": name,
                "kind": "upstream.upstream",
                "upstream": "main",
                "layers": [
                    {
                        "kind": "auth.basic_auth",
                        "users": [{"username": name, "password": "secret"}],
                    }
                ],
            }
            services.append(service)
            servers.append(
                {
                    "name": name,
                    "hostnames": list(names),
                    "listeners": ["main"],
                    "service": name,
                }
            )
        config["services"] = services
        config["servers"] = servers
        with running_proxy(tmp_path, config) as proxy:
            for username in [route, "wrong-service"]:
                command = [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--noproxy",
                    "",
                    "--proxy",
                    f"{'socks5h' if protocol == 'socks5' else 'http'}://127.0.0.1:{proxy.port}",
                    "--proxy-user",
                    f"{username}:secret",
                    "--max-time",
                    "5",
                    "--write-out",
                    "\n%{http_code}",
                ]
                if protocol == "http":
                    command.extend(["--proxytunnel", "--proxy-basic"])
                command.append(f"http://{host}:8080/")
                result = await asyncio.to_thread(
                    subprocess.run,
                    command,
                    capture_output=True,
                    timeout=8,
                    env=get_curl_env_without_no_proxy(),
                )
                allowed = username == route and (route != "fallback" or default)
                if allowed:
                    assert result.returncode == 0, result.stderr
                    assert result.stdout == b"socks\n200", result.stdout
                else:
                    assert result.returncode != 0, result.stdout
            assert peer.connections == (1 if route != "fallback" or default else 0)
            assert len(peer.targets) == peer.connections
            if peer.targets:
                assert peer.targets[0][2] == 8080
                request = peer.requests[0].lower()
                assert b"proxy-authorization:" not in request
