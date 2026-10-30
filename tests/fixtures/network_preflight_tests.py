"""Public contracts for the three direct Cloudflare protocol probes."""

import subprocess

import pytest

from tests.fixtures.network_preflight import check_cloudflare


@pytest.mark.parametrize("failure", [None, 0, 1, 2])
def test_check_cloudflare_probes_http_https_and_h3(
    monkeypatch: pytest.MonkeyPatch, failure: int | None
) -> None:
    for name in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ]:
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    calls: list[tuple[str, str]] = []

    def run(
        command: list[str],
        *,
        env: dict[str, str],
        capture_output: bool,
        text: bool,
        timeout: int,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        assert not any(key.lower().endswith("_proxy") for key in env)
        assert command[:6] == ["curl", "--disable", "--proxy", "", "--noproxy", "*"]
        assert "--ipv4" in command
        assert capture_output and text and not check and timeout == 12
        failed = len(calls) == failure
        calls.append((command[-1], command[-2]))
        return subprocess.CompletedProcess(
            command, 7 if failed else 0, "000" if failed else "301", ""
        )

    monkeypatch.setattr(subprocess, "run", run)
    result = check_cloudflare()
    assert (result is None) == (failure is None)
    expected = [
        ("http://cloudflare.com/", "--http1.1"),
        ("https://cloudflare.com/", "--http1.1"),
        ("https://cloudflare.com/", "--http3-only"),
    ]
    assert calls == (expected if failure is None else expected[: failure + 1])
    if result is not None:
        assert calls[-1][0] in result and calls[-1][1] in result
