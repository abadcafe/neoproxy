"""module: matrix_scenario; responsibility: own a two-hop curl experiment.
Public operations: run_exchange. Data entities: none.
Tests: chain matrix local, Cloudflare and authentication process contracts.
"""

from contextlib import ExitStack
from pathlib import Path
from time import monotonic
from typing import Literal

from .chain_diagnostics import record_chain
from .matrix_configuration import write_node
from .matrix_curl import curl_command
from .matrix_model import AuthCase, CertificateFiles, ChainCase
from .matrix_observation import Exchange, OriginRequest, read_access
from .matrix_origin import ResponseTiming, local_origin
from .ports import get_unique_port


def run_exchange(
    directory: Path,
    case: ChainCase,
    target: Literal["local", "cloudflare"],
    certs: CertificateFiles,
    *,
    entry_auth: AuthCase | None = None,
    relay_auth: AuthCase | None = None,
    origin_timing: ResponseTiming | None = None,
    tunnel_idle_timeout: str = "10s",
) -> Exchange:
    if target == "cloudflare":
        tunnel_idle_timeout = "30s"
    directory.mkdir(parents=True, exist_ok=True)
    entry_dir, relay_dir = directory / "entry", directory / "relay"
    entry_port, relay_port = get_unique_port(), get_unique_port()
    # Local exchanges complete in milliseconds. Let abandoned curl QUIC
    # connections expire before the 3s transport shutdown budget. Timing
    # experiments and public origins retain the normal transport window.
    quic_idle_timeout = "500ms" if target == "local" and origin_timing is None else "5s"
    relay_config = write_node(
        relay_dir,
        case.relay,
        relay_port,
        certs,
        listener_auth=relay_auth,
        quic_idle_timeout=quic_idle_timeout,
        upstream_io_timeout="30s" if target == "cloudflare" else "10s",
    )
    entry_config = write_node(
        entry_dir,
        case.entry,
        entry_port,
        certs,
        listener_auth=entry_auth,
        next_peer=(case.relay, relay_port),
        next_auth=relay_auth,
        tunnel_idle_timeout=tunnel_idle_timeout,
        quic_idle_timeout=quic_idle_timeout,
        upstream_io_timeout="30s" if target == "cloudflare" else "10s",
    )
    sent_body = b"matrix-upload\x00\xff\n" * 1024
    origin_requests: list[OriginRequest] = []
    with ExitStack() as resources:
        url = f"{case.scheme}://cloudflare.com/"
        if target == "local":
            origin = resources.enter_context(
                local_origin(case.scheme, certs, origin_timing)
            )
            url = origin.url
            origin_requests = origin.requests
        with record_chain(
            {"entry": entry_dir, "relay": relay_dir},
            {
                "case": case.label,
                "target": target,
                "entry_auth": entry_auth.model_dump_json() if entry_auth else "none",
                "relay_auth": relay_auth.model_dump_json() if relay_auth else "none",
            },
        ) as diagnostics:
            relay = diagnostics.start_proxy("relay", relay_config)
            entry = diagnostics.start_proxy("entry", entry_config)
            # Both nodes must report READY=1 before any curl request or
            # exchange timing starts. Process exit is a setup failure.
            assert relay.wait_ready(), "relay exited before READY=1"
            assert entry.wait_ready(), "entry exited before READY=1"
            started = monotonic()
            result = diagnostics.run_curl(
                curl_command(
                    entry_dir,
                    case,
                    entry_port,
                    url,
                    certs,
                    entry_auth,
                    sent_body,
                )
            )
            elapsed = monotonic() - started
    values = result.stdout.strip().split()
    http_status, connect_status = (
        (int(value) for value in values) if len(values) == 2 else (0, 0)
    )
    body_path = entry_dir / "curl.body"
    body = (
        body_path.read_bytes() if body_path.is_file() and case.method != "HEAD" else b""
    )
    return Exchange(
        result.returncode,
        http_status,
        connect_status,
        result.stderr,
        body,
        sent_body,
        read_access(entry_dir),
        read_access(relay_dir),
        list(origin_requests),
        elapsed,
    )
