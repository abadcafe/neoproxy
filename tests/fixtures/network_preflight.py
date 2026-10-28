"""Check direct reachability of the public matrix origin before workers start.

Public operations: check_baidu. Data entities: none.
Tests: network_preflight_tests.py.
"""

import os
import subprocess


def check_baidu() -> str | None:
    """Return a diagnostic when either origin scheme cannot be reached directly."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    }
    for scheme in ("http", "https"):
        url = f"{scheme}://www.baidu.com/"
        try:
            result = subprocess.run(
                [
                    "curl",
                    "--disable",
                    "--proxy",
                    "",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--show-error",
                    "--output",
                    os.devnull,
                    "--write-out",
                    "%{http_code}",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "10",
                    url,
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return f"Baidu direct-network preflight failed for {url}: {error}"
        if result.returncode != 0 or result.stdout.strip() != "200":
            return (
                f"Baidu direct-network preflight failed for {url}: "
                f"curl exit={result.returncode}, HTTP={result.stdout.strip()!r}; "
                f"{result.stderr.strip()}. Proxy environment and curlrc are disabled."
            )
    return None
