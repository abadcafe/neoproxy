"""Central E2B policy API/cache and TCP egress contracts, exercised with curl."""

import asyncio
from pathlib import Path

import pytest

from tests.fixtures.certificates import generate_test_certificates
from tests.fixtures.configuration import ConfigDict
from tests.fixtures.discovery_dns import discovery_dns
from tests.fixtures.e2b_policy_peer import PolicyReply, policy_api
from tests.fixtures.e2b_scenario import ListenerProtocol, configuration, curl_policy
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.socks5_upstream import socks_peer


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["http", "https", "http3"])
@pytest.mark.parametrize("tunnel", [False, True])
async def test_policy_filters_all_http_listeners(
    tmp_path: Path, protocol: ListenerProtocol, tunnel: bool
) -> None:
    cert, key, _, _ = generate_test_certificates(str(tmp_path))
    async with policy_api() as api, socks_peer() as socks:
        api.replies["allowed"] = PolicyReply(
            policy={"egressProxy": {"address": f"127.0.0.1:{socks.port}"}}
        )
        api.replies["denied"] = PolicyReply(policy={"denyOut": ["0.0.0.0/0", "::/0"]})
        with running_proxy(
            tmp_path,
            configuration(api.port, protocol=protocol, certificate=cert, key=key),
        ) as proxy:
            for sandbox in [None, "denied", "allowed"]:
                result = await curl_policy(
                    proxy.port,
                    "http://1.1.1.1/",
                    sandbox,
                    tunnel=tunnel,
                    protocol=protocol,
                )
                assert result.status == (200 if sandbox == "allowed" else 403), result
                if sandbox == "allowed":
                    assert result.code == 0 and result.body == b"socks", result
            assert socks.connections == 1
            assert [request.sandbox_id for request in api.requests] == [
                "denied",
                "allowed",
            ]


@pytest.mark.asyncio
async def test_process_shared_cache_and_different_sandbox_parallelism(
    tmp_path: Path,
) -> None:
    async with policy_api() as api, socks_peer() as socks:
        api.gate = asyncio.Event()
        allow: ConfigDict = {"egressProxy": {"address": f"127.0.0.1:{socks.port}"}}
        api.replies = {
            "one": PolicyReply(policy=allow),
            "two": PolicyReply(policy=allow),
        }
        with running_proxy(tmp_path, configuration(api.port)) as proxy:
            tasks = [
                asyncio.create_task(curl_policy(proxy.port, "http://1.1.1.1/", sandbox))
                for sandbox in ["one", "two"] + ["one"] * 11
            ]
            first = await asyncio.wait_for(api.arrived.get(), 3)
            second = await asyncio.wait_for(api.arrived.get(), 3)
            assert {first.sandbox_id, second.sandbox_id} == {"one", "two"}
            api.gate.set()
            responses = await asyncio.gather(*tasks)
            assert all(
                result.status == 200 and result.code == 0 for result in responses
            ), responses
            assert len(api.requests) == 2
            assert socks.connections == 13  # SOCKS5 tunnels are never pooled.


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "rollback",
        "wrong_id",
        "bad_json",
        "missing_etag",
        "status",
        "ttl_zero",
        "invalid_policy",
        "timeout",
    ],
)
async def test_expiry_failure_retains_remote_policy_and_version(
    tmp_path: Path, failure: str
) -> None:
    async with policy_api() as api:
        api.replies["sandbox"] = PolicyReply(
            version=10, ttl=1, policy={"denyOut": ["0.0.0.0/0"]}
        )
        with running_proxy(tmp_path, configuration(api.port)) as proxy:
            assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 403
            await asyncio.sleep(1.05)
            api.replies["sandbox"] = PolicyReply(
                version=9 if failure == "rollback" else 11,
                sandbox_id="other" if failure == "wrong_id" else None,
                invalid_body=failure == "bad_json",
                omit_etag=failure == "missing_etag",
                status=503 if failure == "status" else 200,
                ttl=0 if failure == "ttl_zero" else 60,
                policy={"denyOut": ["invalid.test"]}
                if failure == "invalid_policy"
                else {},
            )
            if failure == "timeout":
                api.gate = asyncio.Event()
            assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 403
            assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 403
            assert len(api.requests) == 2
            assert api.requests[-1].etag == '"10"'


@pytest.mark.asyncio
async def test_matching_304_renews_and_new_version_replaces_policy(
    tmp_path: Path,
) -> None:
    async with policy_api() as api, socks_peer() as socks:
        api.replies["sandbox"] = PolicyReply(
            version=1, ttl=1, policy={"denyOut": ["0.0.0.0/0"]}
        )
        with running_proxy(tmp_path, configuration(api.port)) as proxy:
            assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 403
            await asyncio.sleep(1.05)
            api.replies["sandbox"] = PolicyReply(version=1, status=304, ttl=1)
            assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 403
            assert len(api.requests) == 2
            await asyncio.sleep(1.05)
            api.replies["sandbox"] = PolicyReply(
                version=2,
                policy={"egressProxy": {"address": f"127.0.0.1:{socks.port}"}},
            )
            result = await curl_policy(proxy.port, "http://1.1.1.1/")
            assert result.status == 200 and result.body == b"socks", result
            assert len(api.requests) == 3 and api.requests[-1].etag == '"1"'


@pytest.mark.asyncio
async def test_cold_failure_default_cached_without_remote_etag(tmp_path: Path) -> None:
    async with policy_api() as api:
        api.replies["sandbox"] = PolicyReply(status=304)
        with running_proxy(
            tmp_path,
            configuration(api.port, default={"denyOut": ["0.0.0.0/0"]}),
        ) as proxy:
            for _ in range(3):
                assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 403
            assert len(api.requests) == 1 and api.requests[0].etag is None
            await asyncio.sleep(2.05)
            assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 403
            assert len(api.requests) == 2 and api.requests[-1].etag is None


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["allowed.test", "sub.allowed.test", "other.test"])
async def test_domains_use_pool_dns_and_socks_remote_dns(
    tmp_path: Path, domain: str
) -> None:
    async with policy_api() as api, socks_peer() as socks, discovery_dns() as dns:
        dns.addresses = ("1.1.1.1",)
        socks.method = 2
        api.replies["sandbox"] = PolicyReply(
            policy={
                "allowOut": ["allowed.test", "*.allowed.test"],
                "denyOut": ["0.0.0.0/0", "::/0"],
                "egressProxy": {
                    "address": f"127.0.0.1:{socks.port}",
                    "username": "user",
                    "password": "pass",
                },
            }
        )
        with running_proxy(
            tmp_path, configuration(api.port, dns_port=dns.port)
        ) as proxy:
            result = await curl_policy(proxy.port, f"http://{domain}/", tunnel=True)
            assert result.status == (403 if domain == "other.test" else 200), result
        assert any(name == domain for name, _ in dns.queries)
        if domain != "other.test":
            assert socks.targets == [(3, domain.encode(), 80)]
            assert socks.users == [(b"user", b"pass")]
        else:
            assert socks.connections == 0


@pytest.mark.asyncio
async def test_domain_allow_cannot_rebind_to_private_destination(
    tmp_path: Path,
) -> None:
    async with policy_api() as api, discovery_dns() as dns, socks_peer() as socks:
        api.replies["sandbox"] = PolicyReply(
            policy={
                "allowOut": ["allowed.test"],
                "egressProxy": {"address": f"127.0.0.1:{socks.port}"},
            }
        )
        with running_proxy(
            tmp_path, configuration(api.port, dns_port=dns.port)
        ) as proxy:
            assert (
                await curl_policy(proxy.port, "http://allowed.test/", tunnel=True)
            ).status == 403
            assert socks.connections == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("tunnel", [False, True])
async def test_direct_authorization_rechecks_before_reusing_connections(
    tmp_path: Path, tunnel: bool
) -> None:
    from tests.fixtures.origin_peer import PeerConfig, origin_peer

    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    async with (
        policy_api() as api,
        origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as origin,
    ):
        api.replies["sandbox"] = PolicyReply(
            ttl=1, policy={"allowOut": ["127.0.0.1"], "denyOut": ["0.0.0.0/0"]}
        )
        with running_proxy(tmp_path, configuration(api.port, certificate=ca)) as proxy:
            target = f"https://127.0.0.1:{origin.port}/"
            result = await curl_policy(
                proxy.port,
                target if tunnel else target.replace("https://", "http://"),
                tunnel=tunnel,
                absolute_target=None if tunnel else target,
            )
            assert result.status == 200 and result.code == 0, result
            assert len(origin.requests) == 1
            assert "x-sandbox-id" not in origin.requests[0].headers
            api.replies["sandbox"] = PolicyReply(
                version=2, policy={"denyOut": ["0.0.0.0/0"]}
            )
            await asyncio.sleep(1.05)
            result = await curl_policy(
                proxy.port,
                target if tunnel else target.replace("https://", "http://"),
                tunnel=tunnel,
                absolute_target=None if tunnel else target,
            )
            assert result.status == 403, result
            assert len(origin.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("dns_servers", [None, [], ["9.9.9.9"]])
async def test_dns_servers_are_reachability_exceptions(
    tmp_path: Path, dns_servers: list[str] | None
) -> None:
    async with policy_api() as api, socks_peer() as socks:
        policy: ConfigDict = {
            "allowOut": ["allowed.test"],
            "denyOut": ["0.0.0.0/0", "::/0"],
            "egressProxy": {"address": f"127.0.0.1:{socks.port}"},
        }
        if dns_servers is not None:
            policy["dnsServers"] = list(dns_servers)
        api.replies["sandbox"] = PolicyReply(policy=policy)
        with running_proxy(tmp_path, configuration(api.port)) as proxy:
            target = "9.9.9.9" if dns_servers else "8.8.8.8"
            result = await curl_policy(proxy.port, f"http://{target}:53/", tunnel=True)
            assert result.status == (403 if dns_servers == [] else 200), result


@pytest.mark.asyncio
@pytest.mark.parametrize("valid_identity", [True, False])
async def test_socks_tls_trust_and_server_identity(
    tmp_path: Path, valid_identity: bool
) -> None:
    import ssl

    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    async with policy_api() as api, socks_peer(tls) as socks:
        api.replies["sandbox"] = PolicyReply(
            policy={
                "egressProxy": {
                    "address": f"127.0.0.1:{socks.port}",
                    "tls": {
                        "enabled": True,
                        "serverName": "127.0.0.1" if valid_identity else "wrong.test",
                        "caCert": Path(ca).read_text(),
                    },
                }
            }
        )
        with running_proxy(tmp_path, configuration(api.port)) as proxy:
            result = await curl_policy(proxy.port, "http://1.1.1.1/")
            assert result.status == (200 if valid_identity else 502), result
            if valid_identity:
                assert result.code == 0 and result.body == b"socks", result
                assert len(socks.requests) == 1
                assert b"x-sandbox-id" not in socks.requests[0].lower()


@pytest.mark.asyncio
async def test_layer_configurations_have_isolated_default_caches(
    tmp_path: Path,
) -> None:
    from tests.fixtures.ports import get_unique_port

    async with policy_api() as api, socks_peer() as socks:
        api.replies["sandbox"] = PolicyReply(status=503)
        config = configuration(
            api.port,
            default={"egressProxy": {"address": f"127.0.0.1:{socks.port}"}},
        )
        other_port = get_unique_port()
        listeners = config["listeners"]
        services = config["services"]
        servers = config["servers"]
        assert isinstance(listeners, list)
        assert isinstance(services, list)
        assert isinstance(servers, list)
        listeners.append(
            {"name": "other", "kind": "http", "addresses": [f"127.0.0.1:{other_port}"]}
        )
        services.append(
            {
                "name": "other",
                "kind": "upstream.upstream",
                "upstream": "direct",
                "layers": [
                    {
                        "kind": "e2b.sandbox_network_policy",
                        "default_policy": {"denyOut": ["0.0.0.0/0", "::/0"]},
                    }
                ],
            }
        )
        servers.append({"name": "other", "listeners": ["other"], "service": "other"})
        with running_proxy(tmp_path, config) as proxy:
            for _ in range(2):
                assert (await curl_policy(proxy.port, "http://1.1.1.1/")).status == 200
                assert (await curl_policy(other_port, "http://1.1.1.1/")).status == 403
            assert len(api.requests) == 2


@pytest.mark.asyncio
async def test_identity_is_encoded_in_policy_query(tmp_path: Path) -> None:
    sandbox = "sandbox&version=other"
    async with policy_api() as api, socks_peer() as socks:
        api.replies[sandbox] = PolicyReply(
            policy={"egressProxy": {"address": f"127.0.0.1:{socks.port}"}}
        )
        with running_proxy(tmp_path, configuration(api.port)) as proxy:
            result = await curl_policy(proxy.port, "http://1.1.1.1/", sandbox)
            assert result.code == 0 and result.status == 200, result
            assert len(api.requests) == 1 and api.requests[0].sandbox_id == sandbox


@pytest.mark.asyncio
@pytest.mark.parametrize("tunnel", [False, True])
async def test_https_origin_through_authenticated_socks_egress(
    tmp_path: Path, tunnel: bool
) -> None:
    from tests.fixtures.origin_peer import PeerConfig, origin_peer

    cert, key, ca, _ = generate_test_certificates(str(tmp_path))
    relay_config: ConfigDict = {
        "server_threads": 1,
        "plugins": {"upstream": {"upstreams": [{"name": "direct"}]}, "auth": {}},
        "listeners": [{"name": "main", "kind": "socks5"}],
        "services": [
            {
                "name": "main",
                "kind": "upstream.upstream",
                "upstream": "direct",
                "layers": [
                    {
                        "kind": "auth.basic_auth",
                        "users": [{"username": "sandbox", "password": "secret"}],
                    }
                ],
            }
        ],
        "servers": [{"name": "main", "listeners": ["main"], "service": "main"}],
    }
    async with (
        policy_api() as api,
        origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as origin,
    ):
        with running_proxy(tmp_path / "relay", relay_config) as relay:
            api.replies["sandbox"] = PolicyReply(
                policy={
                    "egressProxy": {
                        "address": f"127.0.0.1:{relay.port}",
                        "username": "sandbox",
                        "password": "secret",
                    }
                }
            )
            with running_proxy(
                tmp_path / "central", configuration(api.port, certificate=ca)
            ) as proxy:
                target = f"https://127.0.0.1:{origin.port}/"
                result = await curl_policy(
                    proxy.port,
                    target if tunnel else target.replace("https://", "http://"),
                    tunnel=tunnel,
                    absolute_target=None if tunnel else target,
                )
                assert result.code == 0 and result.status == 200, result
                assert len(origin.requests) == 1
                assert origin.requests[0].alpn == "http/1.1"
                assert "x-sandbox-id" not in origin.requests[0].headers
                assert "proxy-authorization" not in origin.requests[0].headers


@pytest.mark.asyncio
async def test_pool_dns_filters_each_ip_before_balancing(tmp_path: Path) -> None:
    from tests.fixtures.origin_peer import PeerConfig, origin_peer

    cert, key, ca, _ = generate_test_certificates(
        str(tmp_path), san_entries=["origin.test"]
    )
    async with (
        policy_api() as api,
        discovery_dns() as dns,
        origin_peer(PeerConfig(certificate=cert, key=key, wire="h1")) as allowed,
    ):
        async with origin_peer(
            PeerConfig(
                certificate=cert, key=key, wire="h1", host="::1", port=allowed.port
            )
        ) as denied:
            dns.addresses = ("::1", "127.0.0.1")
            api.replies["sandbox"] = PolicyReply(
                policy={"allowOut": ["127.0.0.1"], "denyOut": ["0.0.0.0/0", "::/0"]}
            )
            with running_proxy(
                tmp_path,
                configuration(api.port, certificate=ca, dns_port=dns.port),
            ) as proxy:
                for _ in range(4):
                    result = await curl_policy(
                        proxy.port,
                        f"http://origin.test:{allowed.port}/",
                        absolute_target=f"https://origin.test:{allowed.port}/",
                    )
                    assert result.code == 0 and result.status == 200, result
                assert len(allowed.requests) == 4 and not denied.requests
                assert len(api.requests) == 1
                assert len(dns.queries) == 2  # One TTL-cached A/AAAA lookup.
