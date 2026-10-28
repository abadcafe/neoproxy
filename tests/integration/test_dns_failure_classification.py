"""Process contracts for DNS diagnostics across forwarding transports."""

import http.client
from pathlib import Path

import pytest

from tests.fixtures.configuration import ConfigDict
from tests.fixtures.http_scenario import running_proxy


@pytest.mark.parametrize("transport", ["direct", "http", "https", "http3"])
@pytest.mark.parametrize("method", ["GET", "CONNECT"])
def test_dns_failure_returns_bad_gateway_with_dns_diagnostic(
    tmp_path: Path, transport: str, method: str
) -> None:
    # Empty DNS labels fail getaddrinfo locally, without relying on a public
    # resolver's response or availability. The authority is valid URI syntax.
    destination = "missing..invalid:80"
    upstream: ConfigDict = {"name": "relay"}
    if transport != "direct":
        upstream["addresses"] = [
            {"address": destination, "address_protocol": transport}
        ]
    config: ConfigDict = {
        "server_threads": 1,
        "plugins": {"upstream": {"upstreams": [upstream]}},
        "listeners": [{"name": "main", "kind": "http"}],
        "services": [
            {
                "name": "relay",
                "kind": "upstream.upstream",
                "upstream": "relay",
            }
        ],
        "servers": [{"name": "relay", "service": "relay", "listeners": ["main"]}],
    }
    with running_proxy(tmp_path, config) as proxy:
        connection = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=3)
        try:
            target = destination if method == "CONNECT" else f"http://{destination}/"
            connection.request(method, target)
            response = connection.getresponse()
            _ = response.read()
            assert response.status == 502
            assert "error=dns_error" in response.getheader("proxy-status", "")
        finally:
            connection.close()
