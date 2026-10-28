"""Process contracts for HTTP/3 upstream pool retention policy."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.discovery_scenario import curl_forward
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.origin_peer import PeerConfig, origin_peer


@pytest.mark.asyncio
@pytest.mark.parametrize("max_connections", [1, 2])
async def test_chain_h3_pool_respects_reuse_policy(
    tmp_path: Path, max_connections: int
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as peer:
        config: ConfigDict = {
            "server_threads": 4,
            "plugins": {
                "upstream": {
                    "upstreams": [
                        {
                            "name": "relay",
                            "addresses": [
                                {
                                    "address": f"127.0.0.1:{peer.port}",
                                    "address_protocol": "http3",
                                }
                            ],
                        }
                    ],
                    "connection_pools": [
                        {
                            "name": "default",
                            "certificates": {"server_ca_path": ca},
                            "http3_pool_max_connections_per_host": max_connections,
                        }
                    ],
                }
            },
            "listeners": [{"name": "main", "kind": "http"}],
            "services": [
                {"name": "relay", "kind": "upstream.upstream", "upstream": "relay"}
            ],
            "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
        }
        plugins = config["plugins"]
        assert isinstance(plugins, dict)
        plugin = plugins["upstream"]
        assert isinstance(plugin, dict)
        upstreams = plugin["upstreams"]
        assert isinstance(upstreams, list)
        upstreams.append(
            {
                "name": "other",
                "addresses": [
                    {"address": f"127.0.0.1:{peer.port}", "address_protocol": "http3"}
                ],
            }
        )
        services = config["services"]
        assert isinstance(services, list)
        services.append(
            {"name": "other", "kind": "upstream.upstream", "upstream": "other"}
        )
        servers = config["servers"]
        assert isinstance(servers, list)
        servers.append(
            {
                "name": "other",
                "hostnames": ["other.test"],
                "service": "other",
                "listeners": ["main"],
            }
        )
        with running_proxy(tmp_path, config) as proxy:
            for index in range(8):
                target = (
                    "http://origin.test/" if index % 2 == 0 else "http://other.test/"
                )
                assert (await curl_forward(proxy.port, target))[0] == 200
            connections = [request.connection for request in peer.requests]
            assert len(set(connections)) == max_connections
            if max_connections == 2:
                assert connections[::2] == [connections[0]] * 4
                assert connections[1::2] == [connections[1]] * 4
            responses = await asyncio.gather(
                *(curl_forward(proxy.port, "http://origin.test/") for _ in range(12))
            )
            assert all(response[0] == 200 for response in responses)
            assert (
                len({request.connection for request in peer.requests})
                == max_connections
            )


@pytest.mark.asyncio
async def test_chain_h3_pool_expires_without_subsequent_request(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as peer:
        config: ConfigDict = {
            "server_threads": 4,
            "plugins": {
                "upstream": {
                    "upstreams": [
                        {
                            "name": "relay",
                            "addresses": [
                                {
                                    "address": f"127.0.0.1:{peer.port}",
                                    "address_protocol": "http3",
                                }
                            ],
                        }
                    ],
                    "connection_pools": [
                        {
                            "name": "default",
                            "certificates": {"server_ca_path": ca},
                            "http3_pool_idle_timeout": "100ms",
                        }
                    ],
                }
            },
            "listeners": [{"name": "main", "kind": "http"}],
            "services": [
                {"name": "relay", "kind": "upstream.upstream", "upstream": "relay"}
            ],
            "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
        }
        with running_proxy(tmp_path, config) as proxy:
            assert (await curl_forward(proxy.port, "http://origin.test/"))[0] == 200
            async with asyncio.timeout(2):
                while peer.closed_connections == 0:
                    await asyncio.sleep(0.02)
