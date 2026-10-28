"""Public contracts for direct public-origin network preflight."""

import subprocess

import pytest

from tests.fixtures.network_preflight import check_baidu


@pytest.mark.parametrize(
    "status,code,failure_scheme",
    [("200", 0, None), ("503", 0, "http"), ("000", 7, "http"), ("403", 0, "https")],
)
def test_check_baidu_checks_both_schemes_without_inherited_proxies(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    code: int,
    failure_scheme: str | None,
) -> None:
    for name in (
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    calls: list[str] = []

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
        assert capture_output and text and not check
        assert timeout == 12
        url = command[-1]
        calls.append(url)
        failed = failure_scheme is not None and url.startswith(failure_scheme + ":")
        return subprocess.CompletedProcess(
            command, code if failed else 0, status if failed else "200", ""
        )

    monkeypatch.setattr(subprocess, "run", run)
    result = check_baidu()
    assert (result is None) == (failure_scheme is None)
    if failure_scheme is not None:
        assert result is not None
        assert f"{failure_scheme}://www.baidu.com/" in result
    assert calls == (
        ["http://www.baidu.com/"]
        if failure_scheme == "http"
        else ["http://www.baidu.com/", "https://www.baidu.com/"]
    )
