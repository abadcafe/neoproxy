"""
HTTP/3 Chain proxy integration tests.

Test target: Verify neoproxy HTTP/3 Chain service behavior
Test nature: Black-box testing through external interface (HTTP)

Basic protocol exchanges belong to chain_matrix_local. This module retains
missing upstream trust, idle/active shutdown, observable WRR distribution and
connection-reuse metadata. Configuration-only startup and duplicate idle
shutdown cases are subsumed by these stronger process contracts.

"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
from contextlib import ExitStack
from pathlib import Path

import pytest
from pydantic import BaseModel, Field

from tests.fixtures.access_log_configuration import enable_access_log
from tests.fixtures.configuration import StringMap
from tests.fixtures.curl import get_curl_env_without_no_proxy
from tests.fixtures.h3_configuration import (
    create_http3_chain_config,
    create_http3_listener_config,
)
from tests.fixtures.http_echo import http_echo_handler
from tests.fixtures.http_request import establish_connect_tunnel
from tests.fixtures.matrix_observation import read_access
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, managed_processes, start_proxy
from tests.fixtures.tcp_peer import create_target_server


def test_chain_missing_server_ca_prevents_readiness(tmp_path: Path) -> None:
    """Startup must fail for the trust file, with no timeout-success escape."""
    ca = tmp_path / "missing-ca.pem"
    config = create_http3_chain_config(
        get_unique_port(), [("127.0.0.1", get_unique_port(), 1)], str(ca), str(tmp_path)
    )
    with managed_processes() as start:
        process = start(config)
        assert not process.wait_ready()
        assert process.wait(timeout=3) == 2
    logs = "".join(
        path.read_text() for path in (tmp_path / "logs").glob("neoproxy.log*")
    )
    assert "server_ca_path" in logs
    assert str(ca) in logs
    assert "plugin initialization failed: upstream: server_ca_path" in logs


@pytest.mark.parametrize("active", [False, True], ids=["idle", "active-tunnel"])
def test_chain_shutdown_releases_connections(
    tmp_path: Path, shared_test_certs: StringMap, active: bool
) -> None:
    """Collapse idle shutdown duplicates and prove the active case has a tunnel."""
    entry_port, relay_port, target_port = (
        get_unique_port(),
        get_unique_port(),
        get_unique_port(),
    )
    target_closed = threading.Event()

    def echo(conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            while data := conn.recv(1024):
                conn.sendall(data)
        except ConnectionResetError:
            pass
        finally:
            conn.close()
            target_closed.set()

    with ExitStack() as resources:
        relay_dir, entry_dir = tmp_path / "relay", tmp_path / "entry"
        relay_dir.mkdir()
        entry_dir.mkdir()
        start = resources.enter_context(managed_processes())
        relay = start(
            create_http3_listener_config(
                relay_port,
                shared_test_certs["cert_path"],
                shared_test_certs["key_path"],
                str(relay_dir),
            )
        )
        assert relay.wait_ready()
        entry = start(
            create_http3_chain_config(
                entry_port,
                [("127.0.0.1", relay_port, 1)],
                shared_test_certs["ca_path"],
                str(entry_dir),
            )
        )
        assert entry.wait_ready()
        if active:
            _, target = create_target_server("127.0.0.1", target_port, echo)
            _ = resources.enter_context(target)
            tunnel = establish_connect_tunnel(
                "127.0.0.1", entry_port, "127.0.0.1", target_port
            )
            assert tunnel is not None
            _ = resources.enter_context(tunnel)
            tunnel.sendall(b"live-tunnel")
            assert tunnel.recv(11) == b"live-tunnel"
            assert not target_closed.is_set()
        entry.send_signal(signal.SIGTERM)
        assert entry.wait(timeout=10 if active else 3) == 0
        if active:
            assert target_closed.wait(timeout=2), "shutdown left the origin tunnel open"
        relay.send_signal(signal.SIGTERM)
        assert relay.wait(timeout=5) == 0


class TestWRRLoadBalancing:
    """Real H3 relays must receive the configured 2:1 request distribution."""

    def test_wrr_weight_distribution(self, shared_test_certs: StringMap) -> None:
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()
        temp_dir3 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port1 = get_unique_port()
        h3_port2 = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc1: BytesProcess | None = None
        h3_proc2: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            # Generate certificates once - both HTTP/3 listeners use the same CA
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Create target echo server
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            # Start HTTP/3 listener 1 (weight 2)
            h3_config1 = create_http3_listener_config(
                proxy_port=h3_port1,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc1 = start_proxy(h3_config1)
            assert h3_proc1.wait_ready(), "HTTP/3 listener 1 failed to start"

            # Start HTTP/3 listener 2 (weight 1)
            h3_config2 = create_http3_listener_config(
                proxy_port=h3_port2,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir2,
            )
            h3_proc2 = start_proxy(h3_config2)
            assert h3_proc2.wait_ready(), "HTTP/3 listener 2 failed to start"

            # Observe selected peers on completed CONNECT requests.
            # Startup alone cannot prove that both relays receive traffic.
            # Start chain service with weights 2:1
            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[
                    ("127.0.0.1", h3_port1, 2),
                    ("127.0.0.1", h3_port2, 1),
                ],
                ca_path=ca_path,
                temp_dir=temp_dir3,
            )
            enable_access_log(chain_config, ["upstream.connection.peer"])
            chain_proc = start_proxy(chain_config)
            assert chain_proc.wait_ready(), "HTTP listener failed to start"

            # Send multiple requests through the chain
            # WRR should distribute these across both upstreams
            for i in range(6):
                result = subprocess.run(
                    [
                        "curl",
                        "-s",
                        "-p",
                        "-x",
                        f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d",
                        f"request_{i}",
                        "--max-time",
                        "5",
                    ],
                    capture_output=True,
                    text=True,
                    env=get_curl_env_without_no_proxy(),
                    timeout=10,
                )
                assert result.returncode == 0, result.stderr
                assert f"request_{i}" in result.stdout

            chain_proc.send_signal(signal.SIGTERM)
            assert chain_proc.wait(timeout=10) == 0
            peers = [
                entry.extensions["upstream.connection.peer"]
                for entry in read_access(Path(temp_dir3))
            ]
            assert len(peers) == 6
            assert peers.count(f"127.0.0.1:{h3_port1}") == 4
            assert peers.count(f"127.0.0.1:{h3_port2}") == 2

            # Verify both listeners are still running (not crashed)
            assert h3_proc1.poll() is None, "HTTP/3 listener 1 should still be running"
            assert h3_proc2.poll() is None, "HTTP/3 listener 2 should still be running"

        finally:
            if chain_proc:
                chain_proc.kill()
                _ = chain_proc.wait(timeout=5)
            if h3_proc1:
                h3_proc1.kill()
                _ = h3_proc1.wait(timeout=5)
            if h3_proc2:
                h3_proc2.kill()
                _ = h3_proc2.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
            shutil.rmtree(temp_dir3, ignore_errors=True)


class ReuseFields(BaseModel):
    request_id: str = Field(alias="request.id")
    peer: str = Field(alias="upstream.connection.peer")
    reused: bool = Field(alias="upstream.connection.reused")
    handshake_ms: int | None = Field(default=None, alias="upstream.tls.handshake_ms")


class ReuseAccessEntry(BaseModel):
    extensions: ReuseFields


class TestConnectionReuse:
    """Test connection reuse in HTTP/3 chain."""

    def test_connection_reuse_across_requests(
        self, shared_test_certs: StringMap
    ) -> None:
        """
        TC-REUSE-001: QUIC connection is reused across multiple requests.

        Target: Verify that once a QUIC connection is established, subsequent
        requests reuse it instead of creating new connections. This prevents
        fd leaks and ensures optimal resource usage.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Start target echo server
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            # Start HTTP/3 listener
            h3_config = create_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)
            assert h3_proc.wait_ready(), "HTTP/3 listener failed to start"

            # Start chain service
            chain_config = create_http3_chain_config(
                http_port=http_port,
                proxy_group=[("127.0.0.1", h3_port, 1)],
                ca_path=ca_path,
                temp_dir=temp_dir2,
            )
            enable_access_log(
                chain_config,
                [
                    "request.id",
                    "upstream.connection.peer",
                    "upstream.connection.reused",
                    "upstream.tls.handshake_ms",
                ],
            )
            chain_proc = start_proxy(chain_config)
            assert chain_proc.wait_ready(), "HTTP listener failed to start"

            # Send 5 requests through the chain
            for i in range(5):
                result = subprocess.run(
                    [
                        "curl",
                        "-s",
                        "-p",
                        "-x",
                        f"http://127.0.0.1:{http_port}",
                        f"http://127.0.0.1:{target_port}/",
                        "-d",
                        f"request_{i}",
                        "--connect-timeout",
                        "10",
                    ],
                    capture_output=True,
                    text=True,
                    env={**os.environ, "no_proxy": "", "NO_PROXY": ""},
                )
                assert f"request_{i}" in result.stdout, (
                    f"Request {i} failed: "
                    + f"stdout={result.stdout}, stderr={result.stderr}"
                )

            # Gracefully shutdown chain service so WorkerGuard flushes logs
            chain_proc.send_signal(signal.SIGTERM)
            return_code = chain_proc.wait(timeout=10)
            assert return_code == 0, f"Chain exit code: {return_code}"

            access = [
                ReuseAccessEntry.model_validate_json(line)
                for path in (Path(temp_dir2) / "logs").glob("access*")
                for line in path.read_text().splitlines()
            ]
            assert len(access) == 5
            assert [entry.extensions.reused for entry in access] == [
                False,
                True,
                True,
                True,
                True,
            ]
            assert all(
                entry.extensions.peer == f"127.0.0.1:{h3_port}" for entry in access
            )
            assert len({entry.extensions.request_id for entry in access}) == 5
            assert access[0].extensions.handshake_ms is not None
            assert all(entry.extensions.handshake_ms is None for entry in access[1:])

        finally:
            if chain_proc and chain_proc.poll() is None:
                chain_proc.kill()
                _ = chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                _ = h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
