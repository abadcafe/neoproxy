"""module: forward_scenario; responsibility: configure HTTP forwarding peers.
Public operations: ForwardNode, write_forward_node. Data entities: ForwardNode.
Tests: HTTPS forwarding process contracts.
"""

from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from .configuration import ConfigDict, dict_to_yaml

type ProxyKind = Literal["http", "https", "http3"]


class ForwardNode(BaseModel):
    port: int
    listener: ProxyKind = "http"
    ca: str | None = None
    certificate: str
    key: str
    upstream_port: int | None = None
    upstream_kind: ProxyKind = "http"
    username: str | None = None
    upstream_username: str | None = None
    handshake_timeout: str = "1s"
    request_timeout: str = "3s"
    h3_max_connections: int = 2


def write_forward_node(directory: Path, node: ForwardNode) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    upstream: ConfigDict = {"name": "route"}
    if node.upstream_port is not None:
        address: ConfigDict = {
            "address": f"127.0.0.1:{node.upstream_port}",
            "hostname": "proxy.test",
            "address_protocol": node.upstream_kind,
        }
        if node.upstream_username is not None:
            address["user"] = {"username": node.upstream_username, "password": "secret"}
        upstream["addresses"] = [address]
    plugin: ConfigDict = {
        "upstreams": [upstream],
        "upstream_request_timeout": node.request_timeout,
        "connection_pools": [
            {
                "name": "default",
                "http3_pool_max_connections_per_host": node.h3_max_connections,
            }
        ],
    }
    pools = plugin["connection_pools"]
    assert isinstance(pools, list)
    pool = pools[0]
    assert isinstance(pool, dict)
    pool["tls_handshake_timeout"] = node.handshake_timeout
    if node.ca is not None:
        pool["certificates"] = {"server_ca_path": node.ca}
    service: ConfigDict = {
        "name": "forward",
        "kind": "upstream.upstream",
        "upstream": "route",
    }
    plugins: ConfigDict = {"upstream": plugin}
    if node.username is not None:
        plugins["auth"] = {}
        service["layers"] = [
            {
                "kind": "auth.basic_auth",
                "users": [{"username": node.username, "password": "secret"}],
            }
        ]
    server: ConfigDict = {
        "name": "forward",
        "service": "forward",
        "listeners": ["main"],
    }
    if node.listener != "http":
        server["certificates"] = [{"cert_path": node.certificate, "key_path": node.key}]
    config: ConfigDict = {
        "server_threads": 1,
        "plugins": plugins,
        "listeners": [
            {
                "name": "main",
                "kind": node.listener,
                "addresses": [f"127.0.0.1:{node.port}"],
            }
        ],
        "services": [service],
        "servers": [server],
    }
    path = directory / "proxy.yaml"
    _ = path.write_text(dict_to_yaml(config))
    return str(path)
