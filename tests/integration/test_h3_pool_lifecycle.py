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
@pytest.mark.parametrize("max_idle", [0, 1])
async def test_chain_h3_pool_respects_reuse_policy(
    tmp_path: Path, max_idle: int
) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as peer:
        config: ConfigDict = {
            "server_threads": 1,
            "plugins": {
                "upstream": {
                    "certificates": {"server_ca_path": ca},
                    "upstreams": [
                        {
                            "name": "relay",
                            "pool": {
                                "max_idle_per_host": max_idle,
                                "idle_timeout": "90s",
                            },
                            "addresses": [
                                {
                                    "address": f"127.0.0.1:{peer.port}",
                                    "address_protocol": "http3",
                                }
                            ],
                        }
                    ],
                }
            },
            "listeners": [{"name": "main", "kind": "http"}],
            "services": [
                {
                    "name": "relay",
                    "kind": "upstream.upstream",
                    "args": {"upstream": "relay"},
                }
            ],
            "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
        }
        with running_proxy(tmp_path, config) as proxy:
            for _ in range(2):
                assert (await curl_forward(proxy.port, "http://origin.test/"))[0] == 200
            assert len({request.connection for request in peer.requests}) == (
                2 if max_idle == 0 else 1
            )


@pytest.mark.asyncio
async def test_chain_h3_pool_expires_without_subsequent_request(tmp_path: Path) -> None:
    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h3")) as peer:
        config: ConfigDict = {
            "server_threads": 1,
            "plugins": {
                "upstream": {
                    "certificates": {"server_ca_path": ca},
                    "upstreams": [
                        {
                            "name": "relay",
                            "pool": {"idle_timeout": "100ms"},
                            "addresses": [
                                {
                                    "address": f"127.0.0.1:{peer.port}",
                                    "address_protocol": "http3",
                                }
                            ],
                        }
                    ],
                }
            },
            "listeners": [{"name": "main", "kind": "http"}],
            "services": [
                {
                    "name": "relay",
                    "kind": "upstream.upstream",
                    "args": {"upstream": "relay"},
                }
            ],
            "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
        }
        with running_proxy(tmp_path, config) as proxy:
            assert (await curl_forward(proxy.port, "http://origin.test/"))[0] == 200
            async with asyncio.timeout(2):
                while peer.closed_connections == 0:
                    await asyncio.sleep(0.02)
