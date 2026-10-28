"""module: discovery_scenario; responsibility: exercise direct origins with curl.
Public operations: direct_proxy, curl_forward. Data entities: none.
Tests: test_direct_http1.py.
"""

import asyncio
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from .configuration import ConfigDict, dict_to_yaml
from .curl import get_curl_env_without_no_proxy
from .ports import get_unique_port
from .proxy_process import BytesProcess, managed_processes, terminate_process


@contextmanager
def direct_proxy(
    directory: Path,
    _certificate: str,
    _key: str,
    ca: str,
    *,
    chain: bool = False,
    dns_port: int | None = None,
    idle_timeout: str = "90s",
    max_idle_per_host: int = 32,
    tls_handshake_timeout: str = "10s",
) -> Generator[int]:
    with managed_processes() as start:
        processes: list[BytesProcess] = []
        upstream_port: int | None = None
        for index in range(2 if chain else 1):
            port = get_unique_port()
            upstream: ConfigDict = {
                "name": "direct",
            }
            if upstream_port is not None:
                upstream = {
                    "name": "relay",
                    "addresses": [
                        {
                            "address": f"127.0.0.1:{upstream_port}",
                            "address_protocol": "http",
                        }
                    ],
                }
            plugin: ConfigDict = {
                "upstreams": [upstream],
                "upstream_request_timeout": "4s",
                "connection_pools": [
                    {
                        "name": "default",
                        "http_pool_idle_timeout": idle_timeout,
                        "https_pool_idle_timeout": idle_timeout,
                        "http_pool_max_idle_connections": max_idle_per_host,
                        "https_pool_max_idle_connections": max_idle_per_host,
                        "certificates": {"server_ca_path": ca},
                        "dns_resolve_timeout": "1s",
                        "tls_handshake_timeout": tls_handshake_timeout,
                    }
                ],
            }
            if dns_port is not None:
                pools = plugin["connection_pools"]
                assert isinstance(pools, list)
                pool = pools[0]
                assert isinstance(pool, dict)
                pool["dns_servers"] = [f"127.0.0.1:{dns_port}"]
            config: ConfigDict = {
                "server_threads": 1,
                "plugins": {"upstream": plugin},
                "listeners": [
                    {"name": "main", "kind": "http", "addresses": [f"127.0.0.1:{port}"]}
                ],
                "services": [
                    {
                        "name": "forward",
                        "kind": "upstream.upstream",
                        "upstream": upstream["name"],
                    }
                ],
                "servers": [
                    {"name": "forward", "listeners": ["main"], "service": "forward"}
                ],
            }
            path = directory / f"discovery-{index}.yaml"
            _ = path.write_text(dict_to_yaml(config))
            process = start(str(path))
            processes.append(process)
            assert process.wait_ready()
            upstream_port = port
        assert upstream_port is not None
        try:
            yield upstream_port
        finally:
            for index, process in enumerate(processes):
                terminate_process(process, force=True)
                stdout, stderr = process.communicate()
                _ = (directory / f"discovery-{index}.log").write_bytes(stdout + stderr)


async def curl_forward(
    entry: int, url: str, payload: bytes | None = None
) -> tuple[int, bytes, bytes]:
    args = [
        "curl",
        "--http1.1",
        "--silent",
        "--show-error",
        "--noproxy",
        "",
        "--proxy",
        f"http://127.0.0.1:{entry}",
        "--max-time",
        "6",
        "--dump-header",
        "-",
        "--request-target",
        url,
    ]
    if payload is not None:
        args.extend(["--data-binary", "@-"])
    args.append(url.replace("https://", "http://", 1))
    result = await asyncio.to_thread(
        subprocess.run,
        args,
        input=payload,
        capture_output=True,
        timeout=8,
        env=get_curl_env_without_no_proxy(),
    )
    assert result.returncode == 0, result.stderr
    headers, separator, body = result.stdout.partition(b"\r\n\r\n")
    assert separator, result.stdout
    return int(headers.split(b" ", 2)[1]), headers, body
