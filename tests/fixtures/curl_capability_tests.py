"""Public contracts for curl's compiled HTTP/3 proxy capability."""

import subprocess
from unittest.mock import patch

import pytest

from tests.fixtures.curl_capability import check_http3_proxy


@pytest.mark.parametrize(
    ("output", "supported"),
    [
        ("curl 8.23.0\nFeatures: HTTP3 HTTPS-proxy\n", False),
        ("curl 8.23.0\nFeatures: HTTP3 HTTPS-proxy proxy-HTTP3\n", True),
        ("curl 8.23.0\nFeatures: HTTP3 proxy-HTTP3-other\n", False),
        ("--proxy-http3 Use HTTP/3 with HTTPS proxy\n", False),
    ],
)
def test_check_http3_proxy_requires_compiled_feature(
    output: str, supported: bool
) -> None:
    with patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(
            ["curl", "--disable", "--version"], 0, output, ""
        ),
    ):
        assert (check_http3_proxy() is None) is supported


def test_check_http3_proxy_reports_command_failure() -> None:
    with patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(["curl"], 1, "", "loader failed"),
    ):
        assert "loader failed" in (check_http3_proxy() or "")


@pytest.mark.parametrize(
    "failure", [FileNotFoundError("curl missing"), subprocess.TimeoutExpired("curl", 5)]
)
def test_check_http3_proxy_reports_unavailable_command(
    failure: OSError | subprocess.TimeoutExpired,
) -> None:
    with patch("subprocess.run", side_effect=failure):
        assert check_http3_proxy() is not None
