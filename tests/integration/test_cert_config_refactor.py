"""
Certificate configuration refactoring integration tests.

Test target: Verify new certificate config naming and per-proxy tls config.
Test nature: Black-box testing through external interface.

Tests verify:
1. http3 listener uses server-level TLS configuration
2. http3_chain accepts server_ca_path inside tls and default_tls
3. Deep merge of tls with default_tls works correctly
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
    wait_for_udp_port_bound,
)

from .utils.http_echo import http_echo_handler

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
    server_threads: int = 1,
) -> str:
    """Create HTTP/3 listener config with NEW architecture (server-level TLS)."""
    config_content = f"""server_threads: {server_threads}

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

listeners:
- name: http3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  listeners: ["http3_main"]
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
    default_user: Optional[Dict[str, str]] = None,
    default_tls: Optional[Dict[str, Any]] = None,
    server_threads: int = 1,
) -> str:
    """Create HTTP/3 chain config with new structure (user and tls separate).

    Args:
        http_port: HTTP listener port.
        proxy_group: List of dicts with keys: address, port, weight, and optional:
            - user: dict with username, password
            - tls: dict with server_ca_path, client_cert_path, client_key_path
        temp_dir: Temp directory for logs.
        default_user: Optional default user with username, password.
        default_tls: Optional default TLS config with same keys as tls.
        server_threads: Worker thread count.
    """
    proxy_lines: list[str] = []
    for pg in proxy_group:
        proxy_lines.append(f"    - address: {pg['address']}:{pg['port']}")
        proxy_lines.append(f"      hostname: localhost")
        proxy_lines.append(f"      weight: {pg['weight']}")
        if "user" in pg and pg["user"]:
            proxy_lines.append("      user:")
            proxy_lines.append(f"        username: \"{pg['user']['username']}\"")
            proxy_lines.append(f"        password: \"{pg['user']['password']}\"")
        if "tls" in pg and pg["tls"]:
            proxy_lines.append("      tls:")
            tls = pg["tls"]
            if "client_cert_path" in tls and tls["client_cert_path"]:
                proxy_lines.append(f"        client_cert_path: \"{tls['client_cert_path']}\"")
            if "client_key_path" in tls and tls["client_key_path"]:
                proxy_lines.append(f"        client_key_path: \"{tls['client_key_path']}\"")
            if "server_ca_path" in tls and tls["server_ca_path"]:
                proxy_lines.append(f"        server_ca_path: \"{tls['server_ca_path']}\"")

    proxy_section = "\n".join(proxy_lines)

    default_user_section = ""
    if default_user:
        default_user_section = f"""
    default_user:
      username: "{default_user['username']}"
      password: "{default_user['password']}\""""

    default_tls_section = ""
    if default_tls:
        default_tls_lines: list[str] = ["    default_tls:"]
        dt = default_tls
        if "client_cert_path" in dt and dt["client_cert_path"]:
            default_tls_lines.append(f"      client_cert_path: \"{dt['client_cert_path']}\"")
        if "client_key_path" in dt and dt["client_key_path"]:
            default_tls_lines.append(f"      client_key_path: \"{dt['client_key_path']}\"")
        if "server_ca_path" in dt and dt["server_ca_path"]:
            default_tls_lines.append(f"      server_ca_path: \"{dt['server_ca_path']}\"")
        default_tls_section = "\n" + "\n".join(default_tls_lines)

    config_content = f"""server_threads: {server_threads}

services:
- name: http3_chain
  kind: http3_chain.http3_chain
  args:
    proxy_group:
{proxy_section}{default_user_section}{default_tls_section}

listeners:
- name: http_main
  kind: http
  addresses: [ "0.0.0.0:{http_port}" ]

servers:
- name: http_proxy
  listeners: ["http_main"]
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

    def test_listener_starts_with_new_field_names(self, shared_test_certs: dict) -> None:
        """
        TC-CERT-REFACTOR-001: HTTP/3 listener starts with server-level TLS config.

        Verifies the listener starts successfully with the new architecture
        where TLS is configured at server level, not listener level.
        """
        temp_dir = tempfile.mkdtemp()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']

            config_path = create_new_http3_listener_config(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "HTTP/3 listener with server-level TLS failed to start"

            assert proxy_proc.poll() is None, \
                "HTTP/3 listener should be running"

        finally:
            if proxy_proc:
                proxy_proc.send_signal(signal.SIGTERM)
                proxy_proc.wait(timeout=10)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test: http3_chain server_ca_path in default_tls
# ==============================================================================


class TestHttp3ChainDefaultTlsServerCa:
    """Verify http3_chain accepts server_ca_path in default_tls."""

    def test_chain_starts_with_default_tls_server_ca(self, shared_test_certs: dict) -> None:
        """
        TC-CERT-REFACTOR-002: http3_chain starts with server_ca_path in default_tls.

        Verifies the chain service accepts the new config structure where
        server_ca_path is inside default_tls instead of at service level.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            config_path = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                }],
                default_tls={"server_ca_path": ca_path},
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

    def test_chain_starts_with_per_proxy_server_ca(self, shared_test_certs: dict) -> None:
        """
        TC-CERT-REFACTOR-003: http3_chain starts with server_ca_path in per-proxy tls.

        Verifies per-proxy tls can contain server_ca_path.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            config_path = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                    "tls": {"server_ca_path": ca_path},
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
# Test: Deep merge of tls with default_tls
# ==============================================================================


class TestTlsDeepMerge:
    """Verify deep merge behavior between proxy tls and default_tls."""

    def test_data_through_chain_with_default_tls(self, shared_test_certs: dict) -> None:
        """
        TC-CERT-REFACTOR-004: Data transmission through chain using default_tls.

        Verifies that server_ca_path from default_tls is used when
        proxy has no tls of its own. End-to-end data test.
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
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

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
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Start chain with server_ca_path in default_tls
            chain_config = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                }],
                default_tls={"server_ca_path": ca_path},
                temp_dir=temp_dir2,
            )
            chain_proc = start_proxy(chain_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "HTTP listener failed to start"

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

    def test_per_proxy_ca_overrides_default(self, shared_test_certs: dict) -> None:
        """
        TC-CERT-REFACTOR-005: Per-proxy server_ca_path overrides default_tls.

        Verifies that when proxy has its own server_ca_path in tls,
        it overrides the one from default_tls. End-to-end data test.
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
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

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
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), \
                "HTTP/3 listener failed to start"

            # Chain: default_tls has a WRONG ca, per-proxy has the CORRECT ca
            chain_config = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                    "tls": {"server_ca_path": ca_path},
                }],
                default_tls={"server_ca_path": "/nonexistent/wrong_ca.pem"},
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

    def test_default_tls_inherited(self, shared_test_certs: dict) -> None:
        """
        TC-CERT-REFACTOR-006: Proxy inherits TLS from default_tls via deep merge.

        Verifies that when proxy has no tls config,
        server_ca_path is inherited from default_tls.
        This test starts the chain service and verifies it accepts the config.
        """
        temp_dir = tempfile.mkdtemp()
        http_port = get_unique_port()
        h3_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            cert_path = shared_test_certs['cert_path']
            key_path = shared_test_certs['key_path']
            ca_path = shared_test_certs['ca_path']

            config_path = create_new_http3_chain_config(
                http_port=http_port,
                proxy_group=[{
                    "address": "127.0.0.1",
                    "port": h3_port,
                    "weight": 1,
                    "user": {"username": "proxy_user", "password": "proxy_pass"},
                }],
                default_tls={
                    "server_ca_path": ca_path,
                },
                temp_dir=temp_dir,
            )

            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), \
                "HTTP listener for chain service failed to start"

            assert proxy_proc.poll() is None, \
                "Chain service should be running with deep-merged tls config"

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

    def test_old_ca_path_at_service_level_not_functional(self, shared_test_certs: dict) -> None:
        """
        TC-CERT-REFACTOR-007: Old ca_path at service level is rejected.

        After refactoring, http3_chain rejects ca_path at service level
        because the struct uses #[serde(deny_unknown_fields)].

        The service should fail to start with a clear error message,
        providing better user experience than silently ignoring the field.
        """
        temp_dir = tempfile.mkdtemp()

        try:
            ca_path = shared_test_certs['ca_path']

            # Chain config uses OLD ca_path at service level (should be rejected)
            config_content = f"""server_threads: 1

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:30589"]

services:
- name: http3_chain
  kind: http3_chain.http3_chain
  args:
    proxy_group:
    - address: 127.0.0.1:30588
      hostname: localhost
      weight: 1
    ca_path: "{ca_path}"

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: http3_chain
"""
            config_path = os.path.join(temp_dir, "old_format.yaml")
            with open(config_path, "w") as f:
                f.write(config_content)

            proc = subprocess.Popen(
                [os.path.abspath(NEOPROXY_BINARY), "--config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                cwd=os.path.dirname(config_path),
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
            # Error is logged to log file (not stderr) since it occurs
            # during service construction in the worker thread
            log_dir = os.path.join(temp_dir, "logs")
            log_content = ""
            if os.path.isdir(log_dir):
                for log_file in os.listdir(log_dir):
                    log_path = os.path.join(log_dir, log_file)
                    if os.path.isfile(log_path):
                        with open(log_path, "r", errors="replace") as f:
                            log_content += f.read()
            assert "ca_path" in log_content, \
                f"Error message should mention 'ca_path', got log: {log_content[:500]}"

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
