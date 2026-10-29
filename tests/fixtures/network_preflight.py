"""Check direct reachability of the public matrix origin before workers start.

Public operations: check_cloudflare. Data entities: none.
Tests: network_preflight_tests.py.
"""

import os
import subprocess


def check_cloudflare() -> str | None:
    """Return a diagnostic when either HTTP version cannot be reached directly."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    }
    for scheme, version in (
        ("http", "--http1.1"),
        ("https", "--http1.1"),
        ("https", "--http3-only"),
    ):
        url = f"{scheme}://cloudflare.com/"
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
                    version,
                    url,
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return (
                f"Cloudflare direct-network preflight failed for "
                f"{url} ({version}): {error}"
            )
        if result.returncode != 0 or result.stdout.strip() != "301":
            return (
                f"Cloudflare direct-network preflight failed for {url} ({version}): "
                f"curl exit={result.returncode}, HTTP={result.stdout.strip()!r}; "
                f"{result.stderr.strip()}. Proxy environment and curlrc are disabled."
            )
    return None
