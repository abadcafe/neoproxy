"""Process contract for DNS metadata on a successful origin."""

from pathlib import Path

import pytest
from pydantic import BaseModel

from tests.fixtures.access_log_configuration import enable_access_log
from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict, JsonValue, dict_to_yaml
from tests.fixtures.discovery_dns import discovery_dns
from tests.fixtures.discovery_scenario import curl_forward
from tests.fixtures.origin_peer import PeerConfig, origin_peer
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import managed_processes


class AccessRecord(BaseModel):
    status: int
    extensions: dict[str, JsonValue]


@pytest.mark.asyncio
async def test_origin_records_successful_dns_metadata(
    tmp_path: Path,
) -> None:
    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as peer:
        async with discovery_dns() as dns:
            entry = get_unique_port()
            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {
                    "upstream": {
                        "upstreams": [{"name": "direct"}],
                        "connection_pools": [
                            {
                                "name": "default",
                                "certificates": {"server_ca_path": ca},
                                "dns_servers": [f"127.0.0.1:{dns.port}"],
                            }
                        ],
                    }
                },
                "listeners": [
                    {
                        "name": "main",
                        "kind": "http",
                        "addresses": [f"127.0.0.1:{entry}"],
                    }
                ],
                "services": [
                    {
                        "name": "forward",
                        "kind": "upstream.upstream",
                        "upstream": "direct",
                    }
                ],
                "servers": [
                    {"name": "forward", "listeners": ["main"], "service": "forward"}
                ],
            }
            path = tmp_path / "proxy.yaml"
            _ = path.write_text(dict_to_yaml(config))
            enable_access_log(
                str(path),
                [
                    "upstream.protocol",
                    "upstream.dns.host",
                    "upstream.dns.duration_ms",
                    "upstream.dns.addresses",
                ],
            )
            with managed_processes() as start:
                proxy = start(str(path))
                assert proxy.wait_ready()
                status, _, body = await curl_forward(
                    entry, f"https://origin.test:{peer.port}/"
                )
                assert status == 200 and body == b"h1"
            entries = [
                AccessRecord.model_validate_json(line)
                for file in (tmp_path / "logs").glob("access*")
                for line in file.read_text().splitlines()
            ]
            assert len(entries) == 1
            assert entries[0].status == 200
            assert entries[0].extensions["upstream.protocol"] == "https"
            assert entries[0].extensions["upstream.dns.host"] == "origin.test"
            assert isinstance(entries[0].extensions["upstream.dns.duration_ms"], int)
            assert entries[0].extensions["upstream.dns.addresses"] == ["127.0.0.1"]
