"""module: matrix_configuration; responsibility: materialize two-hop proxy policy.
Public operations: write_node, supplied_user, supplied_certificate.
Data entities: none. Tests: chain matrix integration tests.
"""

from pathlib import Path

from .configuration import ConfigDict, JsonValue, dict_to_yaml
from .matrix_model import AuthCase, CertificateFiles, ProxyProtocol


def supplied_user(auth: AuthCase | None) -> ConfigDict | None:
    if auth is None or not auth.password_required or auth.fault == "missing_password":
        return None
    return {
        "username": "matrix-user",
        "password": "wrong" if auth.fault == "wrong_password" else "matrix-password",
    }


def supplied_certificate(
    auth: AuthCase | None, certs: CertificateFiles
) -> tuple[str, str] | None:
    if (
        auth is None
        or not auth.certificate_required
        or auth.fault == "missing_certificate"
    ):
        return None
    if auth.fault == "wrong_certificate":
        return certs.alien_cert, certs.alien_key
    return certs.client_cert, certs.client_key


def write_node(
    directory: Path,
    protocol: ProxyProtocol,
    port: int,
    certs: CertificateFiles,
    *,
    listener_auth: AuthCase | None = None,
    next_peer: tuple[ProxyProtocol, int] | None = None,
    next_auth: AuthCase | None = None,
    tunnel_idle_timeout: str = "10s",
) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    upstream: ConfigDict = {"name": "route"}
    trust: ConfigDict = {"server_ca_path": certs.ca}
    if next_peer is not None:
        kind, next_port = next_peer
        address: ConfigDict = {
            "address": f"127.0.0.1:{next_port}",
            "address_protocol": kind,
        }
        if (user := supplied_user(next_auth)) is not None:
            address["user"] = user
        upstream["addresses"] = [address]
        if (pair := supplied_certificate(next_auth, certs)) is not None:
            trust["client_cert_path"], trust["client_key_path"] = pair
    layers: list[JsonValue] = [
        {
            "kind": "access_log.file",
            "args": {
                "writer": "logs/access",
                "context_fields": [
                    "upstream.protocol",
                    "upstream.connection.peer",
                    "upstream.error.kind",
                ],
            },
        }
    ]
    plugins: ConfigDict = {
        "upstream": {
            "certificates": trust,
            "upstream_request_timeout": "10s",
            "tunnel_idle_timeout": tunnel_idle_timeout,
            "upstreams": [upstream],
        },
        "access_log": {
            "writers": [
                {
                    "path_prefix": "logs/access",
                    "format": "json",
                    "flush_interval": "10ms",
                }
            ]
        },
    }
    if listener_auth is not None and listener_auth.password_required:
        plugins["auth"] = {}
        layers.append(
            {
                "kind": "auth.basic_auth",
                "args": {
                    "users": [
                        {"username": "matrix-user", "password": "matrix-password"}
                    ],
                },
            }
        )
    server: ConfigDict = {"name": "main", "listeners": ["main"], "service": "main"}
    if protocol in ("https", "http3"):
        tls: ConfigDict = {
            "certificates": [
                {"cert_path": certs.server_cert, "key_path": certs.server_key}
            ]
        }
        if listener_auth is not None and listener_auth.certificate_required:
            tls["client_ca_certs"] = [certs.ca]
        server["tls"] = tls
    config: ConfigDict = {
        "server_threads": 1,
        "plugins": plugins,
        "listeners": [
            {"name": "main", "kind": protocol, "addresses": [f"127.0.0.1:{port}"]}
        ],
        "services": [
            {
                "name": "main",
                "kind": "upstream.upstream",
                "args": {"upstream": "route"},
                "layers": layers,
            }
        ],
        "servers": [server],
    }
    path = directory / "proxy.yaml"
    _ = path.write_text(dict_to_yaml(config))
    return str(path)
