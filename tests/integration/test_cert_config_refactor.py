"""
Certificate configuration refactoring integration tests.

Test target: Verify new certificate config naming and per-proxy server_ca_path.
Test nature: Black-box testing through external interface.

Tests verify:
1. http3 listener uses server-level TLS configuration
2. http3_chain accepts server_ca_path inside credential and default_credential
3. Deep merge of credential with default_credential works correctly
"""

import subprocess
import socket
import tempfile
import shutil
import time
import os
import signal
import pytest
from typing import Optional, List, Dict, Any

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    terminate_process,
)

from .utils.http_echo import http_echo_handler

from .test_http3_listener import (
    generate_test_certificates,
    wait_for_udp_port,
)

from .conftest import get_unique_port


# ==============================================================================
# Config helpers using NEW architecture (server-level TLS)
# ==============================================================================


def create_new_http3_listener_config(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str,
    auth_config: Optional[str] = None,
    worker_threads: int = 1,
) -> str:
    """Create HTTP/3 listener config with NEW architecture (server-level TLS)."""
    users_section = ""
    if auth_config:
        users_section = f"""
    users:
{auth_config}"""

    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"{users_section}
  listeners:
  - kind: http3
    args:
      addresses: ["0.0.0.0:{proxy_port}"]
  service: connect_tcp
"""
    config_path = os.path.join(temp_dir, "new_http3_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_new_http3_chain_config(
    http_port: int,
    proxy_group: List[Dict[str, Any]],
    temp_dir: str,
    default_credential: Optional[Dict[str, Any]] = None,
    worker_threads: int = 1,
) -> str:
    """Create HTTP/3 chain config with NEW structure (server_ca_path in credential).

    Args:
        http_port: HTTP listener port.
        proxy_group: List of dicts with keys: address, port, weight, and optional credential dict.
            credential dict can have: server_ca_path, client_cert_path, client_key_path,
            user (dict with username, password).
        temp_dir: Temp directory for logs.
        default_credential: Optional default credential dict with same keys as credential.
        worker_threads: Worker thread count.
    """
    proxy_lines: list[str] = []
    for pg in proxy_group:
        proxy_lines.append(f"    - address: {pg['address']}:{pg['port']}")
        proxy_lines.append(f"      weight: {pg['weight']}")
        if "credential" in pg and pg["credential"]:
            proxy_lines.append("      credential:")
            cred = pg["credential"]
            if "user" in cred and cred["user"]:
                proxy_lines.append("        user:")
                proxy_lines.append(f"          username: \"{cred['user']['username']}\"")
                proxy_lines.append(f"          password: \"{cred['user']['password']}\"")
            if "client_cert_path" in cred and cred["client_cert_path"]:
                proxy_lines.append(f"        client_cert_path: \"{cred['client_cert_path']}\"")
            if "client_key_path" in cred and cred["client_key_path"]:
                proxy_lines.append(f"        client_key_path: \"{cred['client_key_path']}\"")
            if "server_ca_path" in cred and cred["server_ca_path"]:
                proxy_lines.append(f"        server_ca_path: \"{cred['server_ca_path']}\"")

    proxy_section = "\n".join(proxy_lines)

    default_cred_section = ""
    if default_credential:
        default_cred_lines: list[str] = ["    default_credential:"]
        dc = default_credential
        if "user" in dc and dc["user"]:
            default_cred_lines.append("      user:")
            default_cred_lines.append(f"        username: \"{dc['user']['username']}\"")
            default_cred_lines.append(f"        password: \"{dc['user']['password']}\"")
        if "client_cert_path" in dc and dc["client_cert_path"]:
            default_cred_lines.append(f"      client_cert_path: \"{dc['client_cert_path']}\"")
        if "client_key_path" in dc and dc["client_key_path"]:
            default_cred_lines.append(f"      client_key_path: \"{dc['client_key_path']}\"")
        if "server_ca_path" in dc and dc["server_ca_path"]:
            default_cred_lines.append(f"      server_ca_path: \"{dc['server_ca_path']}\"")
        default_cred_section = "\n" + "\n".join(default_cred_lines)

    config_content = f"""worker_threads: {worker_threads}
log_directory: "{temp_dir}/logs"

services:
- name: http3_chain
  kind: http3_chain.http3_chain
  args:
    proxy_group:
{proxy_section}{default_cred_section}

servers:
- name: http_proxy
  listeners:
  - kind: http
    args:
      addresses: [ "0.0.0.0:{http_port}" ]
  service: http3_chain
"""
    config_path = os.path.join(temp_dir, "new_http3_chain_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# Test: http3 listener with server-level TLS
# ==============================================================================


class TestHttp3ListenerNewFieldNames:
    """Verify http3 listener uses server-level TLS configuration."""

    def test_listener_starts_with_new_field_names(self) -> None:
        """
        TC-CERT-REFACTOR-001: HTTP/3 listener starts with server-level TLS config.

        Verifies the listener starts successfully with the new architecture
        where TLS is configured at server level, not listener level.
        """
        temp_dir = tempfile.mkdtemp()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            config_path = create_new_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port("127.0.0.1", h3_port, timeout=5.0), \
                "HTTP/3 listener with server-level TLS failed to start"

            assert proxy_proc.poll() is None, \
                "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test: http3_chain server_ca_path in default_credential
# ==============================================================================


class TestHttp3ChainDefaultCredentialServerCa:
    """Verify http3_chain accepts server_ca_path in default_credential."""

    def test_chain_starts_with_default_credential_server_ca(self) -> None:
        """
        TC-CERT-REFACTOR-002: http3_chain starts with server_ca_path in default_credential.

        Verifies the chain service accepts the new config structure where
        server_ca_path is inside default_credential instead of at service level.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            config_path = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                }],
                default_credential={"server_ca_path": ca_path},
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "HTTP listener for chain service failed to start"

            assert proxy_proc.poll() is None, \
                "Chain service should be running"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_chain_starts_with_per_proxy_server_ca(self) -> None:
        """
        TC-CERT-REFACTOR-003: http3_chain starts with server_ca_path in per-proxy credential.

        Verifies per-proxy credential can contain server_ca_path.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            config_path = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                    "credential": {"server_ca_path": ca_path},
                }],
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "HTTP listener for chain service failed to start"

            assert proxy_proc.poll() is None, \
                "Chain service should be running"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test: Deep merge of credential with default_credential
# ==============================================================================


class TestCredentialDeepMerge:
    """Verify deep merge behavior between proxy credential and default_credential."""

    def test_data_through_chain_with_default_credential(self) -> None:
        """
        TC-CERT-REFACTOR-004: Data transmission through chain using default_credential.

        Verifies that server_ca_path from default_credential is used when
        proxy has no credential of its own. End-to-end data test.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None
        h3_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir1)

            # Start target echo server
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            # Start HTTP/3 listener with server-level TLS
            h3_config = create_new_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port("127.0.0.1", h3_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Start chain with server_ca_path in default_credential
            chain_config = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                }],
                default_credential={"server_ca_path": ca_path},
                temp_dir=temp_dir2,
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "HTTP listener failed to start"

            time.sleep(0.5)

            # Test data transmission
            result = subprocess.run(
                [
                    "curl", "-s", "-p",
                    "-x", f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d", "cert_refactor_test",
                    "--connect-timeout", "10",
                ],
                capture_output=True,
                text=True,
            )

            assert "cert_refactor_test" in result.stdout, \
                f"Expected echo data, got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            if h3_proc:
                h3_proc.send_signal(signal.SIGTERM)
                h3_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_per_proxy_ca_overrides_default(self) -> None:
        """
        TC-CERT-REFACTOR-005: Per-proxy server_ca_path overrides default_credential.

        Verifies that when proxy has its own server_ca_path in credential,
        it overrides the one from default_credential. End-to-end data test.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: Optional[subprocess.Popen] = None
        h3_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir1)

            # Start target echo server
            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            # Start HTTP/3 listener with server-level TLS
            h3_config = create_new_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
            )
            h3_proc = start_proxy(h3_config)
            assert wait_for_udp_port("127.0.0.1", h3_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Chain: default_credential has a WRONG ca, per-proxy has the CORRECT ca
            chain_config = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                    "credential": {"server_ca_path": ca_path},
                }],
                default_credential={"server_ca_path": "/nonexistent/wrong_ca.pem"},
                temp_dir=temp_dir2,
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "HTTP listener failed to start"

            time.sleep(0.5)

            # Should succeed because per-proxy ca overrides the wrong default
            result = subprocess.run(
                [
                    "curl", "-s", "-p",
                    "-x", f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d", "override_test",
                    "--connect-timeout", "10",
                ],
                capture_output=True,
                text=True,
            )

            assert "override_test" in result.stdout, \
                f"Expected echo data (per-proxy CA should override default), " \
                f"got stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            if chain_proc:
                chain_proc.send_signal(signal.SIGTERM)
                chain_proc.wait(timeout=10)
            if h3_proc:
                h3_proc.send_signal(signal.SIGTERM)
                h3_proc.wait(timeout=10)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_default_credential_user_inherited(self) -> None:
        """
        TC-CERT-REFACTOR-006: Proxy inherits user from default_credential via deep merge.

        Verifies that when proxy credential has only server_ca_path,
        user is inherited from default_credential.
        This test starts the chain service and verifies it accepts the config.
        Full auth verification requires an upstream that checks credentials.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            config_path = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                    "credential": {"server_ca_path": ca_path},
                }],
                default_credential={
                    "user": {"username": "default_user", "password": "default_pass"},
                    "server_ca_path": "/some/other/ca.pem",
                },
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "HTTP listener for chain service failed to start"

            assert proxy_proc.poll() is None, \
                "Chain service should be running with deep-merged credential"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test: Old field names should be rejected
# ==============================================================================


class TestOldFieldNamesRejected:
    """Verify old field names are no longer functional after refactoring."""

    def test_old_ca_path_at_service_level_not_functional(self) -> None:
        """
        TC-CERT-REFACTOR-007: Old ca_path at service level is rejected.

        After refactoring, http3_chain rejects ca_path at service level
        because the struct uses #[serde(deny_unknown_fields)].

        The service should fail to start with a clear error message,
        providing better user experience than silently ignoring the field.
        """
        temp_dir = tempfile.mkdtemp()

        try:
            cert_path, key_path, ca_path, _ = generate_test_certificates(temp_dir)

            # Chain config uses OLD ca_path at service level (should be rejected)
            config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: http3_chain
  kind: http3_chain.http3_chain
  args:
    proxy_group:
    - address: 127.0.0.1:30588
      weight: 1
    ca_path: "{ca_path}"

servers:
- name: http_proxy
  listeners:
  - kind: http
    args:
      addresses: [ "0.0.0.0:30589" ]
  service: http3_chain
"""
            config_path = os.path.join(temp_dir, "old_format.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proc = subprocess.Popen(
                [NEOPROXY_BINARY, "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )

            try:
                return_code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                assert False, "Process did not exit within expected time"

            # Service should exit with error code (reject old format)
            assert return_code != 0, \
                f"Service should reject old ca_path at service level, got exit code {return_code}"

            # Verify the error message mentions the unknown field
            stderr_output = proc.stderr.read().decode("utf-8", errors="replace")
            assert "ca_path" in stderr_output, \
                f"Error message should mention 'ca_path', got: {stderr_output}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
