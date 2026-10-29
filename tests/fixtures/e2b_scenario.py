"""module: e2b_scenario; responsibility: exercise central sandbox policies with curl.
Public operations: configuration, curl_policy, CurlResult, ListenerProtocol.
Data entities: CurlResult, ListenerProtocol. Tests: integration/test_e2b_policy.py.
"""

import asyncio
import re
import subprocess
from dataclasses import dataclass
from typing import Literal

from .configuration import ConfigDict
from .curl import get_curl_env_without_no_proxy

type ListenerProtocol = Literal["http", "https", "http3"]


@dataclass(frozen=True)
class CurlResult:
    code: int
    status: int
    body: bytes
    error: bytes


def configuration(
    api_port: int,
    *,
    default: ConfigDict | None = None,
    protocol: ListenerProtocol = "http",
    certificate: str | None = None,
    key: str | None = None,
    dns_port: int | None = None,
) -> ConfigDict:
    pool: ConfigDict = {"name": "default"}
    if dns_port is not None:
        pool["dns_servers"] = [f"127.0.0.1:{dns_port}"]
    if certificate is not None:
        pool["certificates"] = {"server_ca_path": certificate}
    server: ConfigDict = {"name": "main", "listeners": ["main"], "service": "main"}
    if protocol != "http":
        assert certificate is not None and key is not None
        server["certificates"] = [{"cert_path": certificate, "key_path": key}]
    return {
        "server_threads": 4,
        "plugins": {
            "upstream": {
                "upstreams": [{"name": "direct"}],
                "connection_pools": [pool],
            },
            "e2b": {
                "policy_api_url": f"http://127.0.0.1:{api_port}/policy",
                "policy_api_timeout": "1s",
            },
        },
        "listeners": [{"name": "main", "kind": protocol}],
        "services": [
            {
                "name": "main",
                "kind": "upstream.upstream",
                "upstream": "direct",
                "layers": [
                    {
                        "kind": "e2b.sandbox_network_policy",
                        "policy_fallback_ttl": "2s",
                        "default_policy": default if default is not None else {},
                    }
                ],
            }
        ],
        "servers": [server],
    }


async def curl_policy(
    port: int,
    target: str,
    sandbox_id: str | None = "sandbox",
    *,
    tunnel: bool = False,
    protocol: ListenerProtocol = "http",
    absolute_target: str | None = None,
) -> CurlResult:
    scheme = "http" if protocol == "http" else "https"
    args = [
        "curl",
        "--disable",
        "--silent",
        "--show-error",
        "--http1.1",
        "--noproxy",
        "",
        "--proxy",
        f"{scheme}://127.0.0.1:{port}",
        "--proxy-insecure",
        "--insecure",
        "--max-time",
        "8",
        "--write-out",
        "\n%{http_connect}" if tunnel else "\n%{http_code}",
    ]
    transfer_target = target
    if protocol == "http3":
        if tunnel:
            args.extend(["--proxy-http3", "--verbose"])
        else:
            args.extend(
                [
                    "--proxy",
                    "",
                    "--http3-only",
                    "--request-target",
                    absolute_target or target,
                ]
            )
            transfer_target = f"https://127.0.0.1:{port}/"
    if tunnel:
        args.append("--proxytunnel")
    if sandbox_id is not None:
        args.extend(
            ["--proxy-header" if tunnel else "--header", f"x-sandbox-id: {sandbox_id}"]
        )
    if absolute_target is not None:
        args.extend(["--request-target", absolute_target])
    args.append(transfer_target)
    result = await asyncio.to_thread(
        subprocess.run,
        args,
        capture_output=True,
        timeout=10,
        env=get_curl_env_without_no_proxy(),
    )
    body, _, status = result.stdout.rpartition(b"\n")
    assert status.isdigit(), (result.stdout, result.stderr)
    code = int(status)
    if protocol == "http3" and tunnel and code == 0:
        # curl currently leaves http_connect at zero for a rejected H3
        # CONNECT, despite decoding and reporting the actual response.
        response = re.search(rb"CONNECT Response Status (\d{3})", result.stderr)
        if response is not None:
            code = int(response.group(1))
    return CurlResult(result.returncode, code, body, result.stderr)
