"""Check the PATH curl's compiled HTTP/3 proxy support.

Public operations: check_http3_proxy. Data entities: none.
Tests: curl_capability_tests.py.
"""

import subprocess


def check_http3_proxy() -> str | None:
    """Return an actionable failure, or None when proxy-HTTP3 is compiled in."""
    try:
        result = subprocess.run(
            ["curl", "--disable", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"Cannot inspect PATH curl: {error}"
    if result.returncode != 0:
        return f"curl --version failed ({result.returncode}): {result.stderr.strip()}"
    features = {
        feature
        for line in result.stdout.splitlines()
        if line.startswith("Features:")
        for feature in line.removeprefix("Features:").split()
    }
    if "proxy-HTTP3" not in features:
        return (
            "PATH curl requires compiled proxy-HTTP3 support; HTTP3 alone and "
            + "--help listing --proxy-http3 are insufficient.\n"
            + result.stdout.strip()
        )
    return None
