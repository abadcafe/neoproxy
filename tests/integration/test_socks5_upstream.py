"""curl contracts for SOCKS5 upstream tunnels and mixed protocol scheduling."""

import socket
from pathlib import Path

import pytest

from tests.fixtures.configuration import ConfigDict
from tests.fixtures.discovery_scenario import curl_forward
from tests.fixtures.http_scenario import running_proxy
from tests.fixtures.socks5_upstream import configuration, curl_tunnel, socks_peer


@pytest.mark.asyncio
@pytest.mark.parametrize("method,credentials", [(0, False), (0, True), (2, True)])
@pytest.mark.parametrize(
    "authority,kind,host,port",
    [
        ("origin.invalid:8080", 3, b"origin.invalid", 8080),
        ("127.0.0.1:80", 1, socket.inet_pton(socket.AF_INET, "127.0.0.1"), 80),
        ("[::1]:443", 4, socket.inet_pton(socket.AF_INET6, "::1"), 443),
    ],
)
async def test_connect_authentication_and_target_encoding(
    tmp_path: Path,
    method: int,
    credentials: bool,
    authority: str,
    kind: int,
    host: bytes,
    port: int,
) -> None:
    async with socks_peer() as peer:
        peer.method = method
        user: ConfigDict | None = (
            {"username": "alice", "password": "secret"} if credentials else None
        )
        with running_proxy(
            tmp_path, configuration([{"address": f"127.0.0.1:{peer.port}"}], user)
        ) as proxy:
            assert await curl_tunnel(proxy.port, authority) == (200, b"socks")
        assert peer.targets == [(kind, host, port)]
        assert peer.methods == [b"\x00\x02" if credentials else b"\x00"]
        assert peer.users == ([(b"alice", b"secret")] if method == 2 else [])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure,status",
    [("auth", 502), ("method", 502), ("denied", 403), ("refused", 502), ("ttl", 504)],
)
async def test_explicit_rejections_do_not_eject_or_retry(
    tmp_path: Path,
    failure: str,
    status: int,
) -> None:
    async with socks_peer() as bad, socks_peer() as good:
        bad.method = 2 if failure == "auth" else 255 if failure == "method" else 0
        bad.auth_status = 1 if failure == "auth" else 0
        bad.reply = {"denied": 2, "refused": 5, "ttl": 6}.get(failure, 0)
        with running_proxy(
            tmp_path,
            configuration(
                [
                    {"address": f"127.0.0.1:{bad.port}"},
                    {"address": f"127.0.0.1:{good.port}"},
                ],
                {"username": "alice", "password": "wrong"},
            ),
        ) as proxy:
            assert (await curl_tunnel(proxy.port))[0] == status
            assert good.connections == 0
            assert (await curl_tunnel(proxy.port))[0] == 200
            assert (await curl_tunnel(proxy.port))[0] == status
        assert bad.connections == 2
        assert good.connections == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["disconnect", "timeout"])
async def test_transport_failure_retries_and_ejects(
    tmp_path: Path,
    failure: str,
) -> None:
    async with socks_peer() as bad, socks_peer() as good:
        bad.disconnect = failure == "disconnect"
        bad.delay = 1 if failure == "timeout" else 0
        with running_proxy(
            tmp_path,
            configuration(
                [
                    {"address": f"127.0.0.1:{bad.port}"},
                    {"address": f"127.0.0.1:{good.port}"},
                ]
            ),
        ) as proxy:
            for _ in range(3):
                assert await curl_tunnel(proxy.port) == (200, b"socks")
        assert bad.connections == 1
        assert good.connections == 3


@pytest.mark.asyncio
async def test_forward_ineligible_nodes_do_not_change_tunnel_health(
    tmp_path: Path,
) -> None:
    async with socks_peer() as peer:
        with running_proxy(
            tmp_path, configuration([{"address": f"127.0.0.1:{peer.port}"}])
        ) as proxy:
            status, headers, _ = await curl_forward(
                proxy.port, "http://origin.invalid/"
            )
            assert status == 502
            assert b"destination_unavailable" in headers
            assert peer.connections == 0
            assert await curl_tunnel(proxy.port) == (200, b"socks")


@pytest.mark.asyncio
async def test_forward_skips_socks_nodes_in_mixed_upstream(tmp_path: Path) -> None:
    direct = configuration([])
    with running_proxy(tmp_path / "http", direct) as next_proxy:
        async with socks_peer() as peer:
            with running_proxy(
                tmp_path / "entry",
                configuration(
                    [
                        {"address": f"127.0.0.1:{peer.port}", "weight": 100},
                        {
                            "address": f"127.0.0.1:{next_proxy.port}",
                            "address_protocol": "http",
                        },
                    ]
                ),
            ) as proxy:
                for _ in range(3):
                    # The HTTP node returns a DNS error for the requested origin;
                    # its diagnostic proves selection never reached the SOCKS node.
                    status, headers, _ = await curl_forward(
                        proxy.port, "http://unresolvable.invalid/"
                    )
                    assert status == 502
                    assert b"dns_error" in headers
                assert peer.connections == 0
                assert await curl_tunnel(proxy.port) == (200, b"socks")


@pytest.mark.asyncio
async def test_forward_with_only_socks_addresses_is_unavailable_without_dns(
    tmp_path: Path,
) -> None:
    with running_proxy(
        tmp_path, configuration([{"address": "unresolvable.invalid:1080"}])
    ) as proxy:
        status, headers, _ = await curl_forward(proxy.port, "http://origin.invalid/")
        assert status == 502
        assert b"destination_unavailable" in headers
