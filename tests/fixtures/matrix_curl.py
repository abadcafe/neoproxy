"""module: matrix_curl; responsibility: invoke curl over a declared proxy transport.
Public operations: curl_command. Data entities: none.
Tests: two-hop chain matrix process tests.
"""

import base64
from pathlib import Path
from urllib.parse import urlsplit

from .matrix_configuration import supplied_certificate, supplied_user
from .matrix_model import AuthCase, CertificateFiles, ChainCase


def curl_command(
    directory: Path,
    case: ChainCase,
    entry_port: int,
    url: str,
    certs: CertificateFiles,
    auth: AuthCase | None,
    body: bytes,
) -> list[str]:
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--http3-only"
        if case.entry == "http3" and case.mode == "forward"
        else "--http1.1",
        "--noproxy",
        "",
        "--connect-timeout",
        "5",
        "--max-time",
        "15",
        "--trace-ascii",
        str(directory / "curl.trace"),
        "--output",
        str(directory / "curl.body"),
        "--write-out",
        "%{http_code} %{http_connect}",
        "--proxy-cacert",
        certs.ca,
    ]
    if urlsplit(url).hostname == "127.0.0.1":
        command.extend(["--cacert", certs.ca])
    transfer_url = (
        url.replace("https://", "http://", 1) if case.mode == "forward" else url
    )
    if case.entry == "http3" and case.mode == "forward":
        # curl's HTTP/3 proxy option negotiates CONNECT. For ordinary forwarding,
        # connect directly to A and encode the target as H3 pseudo-headers via
        # --request-target. No additional proxy hop or origin connection is used.
        command.extend(["--proxy", "", "--request-target", url, "--cacert", certs.ca])
        transfer_url = f"https://127.0.0.1:{entry_port}/"
        if (user := supplied_user(auth)) is not None:
            token = base64.b64encode(
                f"{user['username']}:{user['password']}".encode()
            ).decode()
            command.extend(["--header", f"Proxy-Authorization: Basic {token}"])
        if (pair := supplied_certificate(auth, certs)) is not None:
            command.extend(["--cert", pair[0], "--key", pair[1]])
    else:
        kind = {
            "http": "http",
            "https": "https",
            "http3": "https",
            "socks5": "socks5h",
        }[case.entry]
        command.extend(["--proxy", f"{kind}://127.0.0.1:{entry_port}"])
        if case.entry == "http3":
            command.append("--proxy-http3")
        if case.entry == "socks5":
            command.append("--socks5-basic")
        if (user := supplied_user(auth)) is not None:
            command.extend(["--proxy-user", f"{user['username']}:{user['password']}"])
        if (pair := supplied_certificate(auth, certs)) is not None:
            command.extend(["--proxy-cert", pair[0], "--proxy-key", pair[1]])
        if case.mode == "tunnel" and case.entry != "socks5":
            command.append("--proxytunnel")
        elif case.mode == "forward":
            command.extend(["--request-target", url])
    if case.method == "HEAD":
        command.append("--head")
        # --head writes received headers to the output file. Separate them from
        # response bodies by discarding that file's contents in the observer.
    elif case.method == "POST":
        payload = directory / "curl.request"
        _ = payload.write_bytes(body)
        command.extend(["--data-binary", f"@{payload}"])
    command.append(transfer_url)
    return command
