"""
Configuration validation integration tests.

Test target: Verify neoproxy configuration validation behavior
Test nature: Black-box testing through external interface (CLI)

Tests verify that invalid/malformed configs are rejected at startup
with appropriate error messages. Runtime behavior tests belong elsewhere.
"""

import subprocess
import tempfile
import os
from typing import Tuple, Optional

from .utils.helpers import NEOPROXY_BINARY, wait_for_process_running
from .conftest import get_unique_port


# ==============================================================================
# Test helper functions
# ==============================================================================


def run_neoproxy_with_config(
    config_content: Optional[str],
    config_path: Optional[str] = None,
    timeout: float = 5.0
) -> Tuple[int, str, str]:
    """
    Run neoproxy with a given configuration.

    Args:
        config_content: Configuration content to write to a temp file
        config_path: Direct path to config file (takes precedence over config_content)
        timeout: Timeout for the process

    Returns:
        Tuple[int, str, str]: Return code, stdout, stderr
    """
    temp_file = None

    if config_path is None:
        if config_content is None:
            raise ValueError("Either config_content or config_path must be provided")
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        )
        temp_file.write(config_content)
        temp_file.close()
        config_path = temp_file.name

    try:
        result = subprocess.run(
            [NEOPROXY_BINARY, "--config", config_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    finally:
        if temp_file is not None:
            os.unlink(temp_file.name)


# ==============================================================================
# Test cases - YAML format errors
# ==============================================================================


class TestYamlFormat:
    """YAML syntax and file existence validation."""

    def test_config_file_not_exist(self) -> None:
        """
        TC-CFG-001: Configuration file does not exist.

        Target: Verify neoproxy outputs friendly error message
                when config file does not exist
        """
        result = subprocess.run(
            [NEOPROXY_BINARY, "--config", "/nonexistent/config/path.yaml"],
            capture_output=True,
            text=True,
            timeout=5.0
        )

        assert result.returncode == 1, \
            f"Expected exit code 1, got {result.returncode}"

        assert "read config file" in result.stderr, \
            f"Expected 'read config file' in error, got: {result.stderr}"

    def test_invalid_yaml_syntax(self) -> None:
        """
        TC-CFG-002: Configuration file has invalid YAML syntax.

        Target: Verify neoproxy reports YAML parsing error
        """
        invalid_yaml = """
server_threads: [
  invalid yaml
services: []
"""
        returncode, stdout, stderr = run_neoproxy_with_config(invalid_yaml)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        error_output = stderr.lower()
        assert "error" in error_output or "parse" in error_output or "expected" in error_output, \
            f"Expected YAML parse error in output, got: {stderr}"



# ==============================================================================
# Test cases - Service kind format errors
# ==============================================================================


class TestServiceKindFormat:
    """Service kind format, plugin/builder existence validation."""

    def test_invalid_kind_missing_dot(self) -> None:
        """
        TC-CFG-003: Service kind has invalid format (missing dot).

        Target: Verify neoproxy reports invalid kind format error
        """
        config = """server_threads: 1

services:
- name: test_service
  kind: echo

servers: []
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "invalid service kind" in stderr or "expected 'plugin_name.service_name'" in stderr, \
            f"Expected invalid kind format error, got: {stderr}"

    def test_plugin_not_found(self) -> None:
        """
        TC-CFG-004: Plugin referenced in kind does not exist.

        Target: Verify neoproxy fails when plugin does not exist.
        """
        config = """server_threads: 1

listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:18080"]

services:
- name: test_service
  kind: unknown_plugin.echo

servers:
- name: test_server
  hostnames: []
  listeners: ["http_main"]
  service: test_service
"""
        returncode, _, _ = run_neoproxy_with_config(config)

        assert returncode != 0, \
            f"Expected non-zero exit code, got {returncode}"

    def test_service_builder_not_found(self) -> None:
        """
        TC-CFG-005: Service builder referenced in kind does not exist.

        Target: Verify neoproxy fails when service builder does not exist.
        """
        config = """server_threads: 1

plugins:
  echo:

listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:18080"]

services:
- name: test_service
  kind: echo.unknown_service

servers:
- name: test_server
  hostnames: []
  listeners: ["http_main"]
  service: test_service
"""
        returncode, _, _ = run_neoproxy_with_config(config)

        assert returncode != 0, \
            f"Expected non-zero exit code, got {returncode}"

    def test_listener_builder_not_found(self) -> None:
        """
        TC-CFG-006: Listener builder referenced in kind does not exist.

        Target: Verify neoproxy fails when listener builder does not exist.
        """
        config = """server_threads: 1

plugins:
  echo:

listeners:
- name: bad_listener
  kind: hyper.unknown_listener
  addresses: ["127.0.0.1:18080"]

services:
- name: echo
  kind: echo.echo

servers:
- name: test_server
  hostnames: []
  listeners: ["bad_listener"]
  service: echo
"""
        returncode, _, _ = run_neoproxy_with_config(config)

        assert returncode != 0, \
            f"Expected non-zero exit code, got {returncode}"

    def test_multiple_kind_errors(self) -> None:
        """
        TC-CFG-009: Multiple kind format errors cause failure.

        Target: Verify neoproxy fails when multiple services have invalid kinds.
        Reports the first error and exits.
        """
        config = """server_threads: 1

listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:18080"]

services:
- name: service1
  kind: echo
- name: service2
  kind: echo

servers:
- name: server1
  hostnames: ["host1.example.com"]
  listeners: ["http_main"]
  service: service1
- name: server2
  hostnames: ["host2.example.com"]
  listeners: ["http_main"]
  service: service2
"""
        returncode, _, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "invalid service kind" in stderr or "expected 'plugin_name.service_name'" in stderr, \
            f"Expected kind format error, got: {stderr}"

    def test_unused_bad_plugin_accepted(self) -> None:
        """
        TC-BASE-002: Unused service with bad plugin does NOT cause failure.

        If a service references a nonexistent plugin but no server references
        that service, the plugin is never instantiated and the proxy starts OK.
        """
        http_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  echo:

listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:{http_port}"]

services:
- name: echo
  kind: echo.echo
- name: unused
  kind: nonexistent.service

servers:
- name: test_server
  hostnames: []
  listeners: ["http_main"]
  service: echo
"""
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        )
        temp_file.write(config)
        temp_file.close()

        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", temp_file.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            running = wait_for_process_running(proc, timeout=1.0)
            assert running, \
                "Proxy should start with unused bad plugin (never instantiated)"
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            os.unlink(temp_file.name)


# ==============================================================================
# Test cases - Field validation errors
# ==============================================================================


class TestFieldValidation:
    """Missing/empty fields, invalid values, unknown fields."""

    def test_missing_addresses_field(self) -> None:
        """
        TC-S5-028: Missing addresses field in listener.

        Target: Verify proxy fails to start when addresses field is missing.
        """
        config = """server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks5_main
  kind: socks5

servers:
- name: socks5_server
  listeners: ["socks5_main"]
  service: direct
"""
        proxy_proc = subprocess.Popen(
            [os.path.abspath(NEOPROXY_BINARY), "--config", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proxy_proc.stdin.write(config)
        proxy_proc.stdin.close()
        try:
            exit_code = proxy_proc.wait(timeout=5.0)
            assert exit_code != 0, \
                f"Expected non-zero exit code for missing addresses, got {exit_code}"
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
            raise AssertionError("Process should have exited")

    def test_empty_addresses_list(self) -> None:
        """
        TC-S5-029: Empty addresses list in listener.

        Target: Verify proxy fails to start when addresses list is empty.
        """
        config = """server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks5_main
  kind: socks5
  addresses: []

servers:
- name: socks5_server
  listeners: ["socks5_main"]
  service: direct
"""
        proxy_proc = subprocess.Popen(
            [os.path.abspath(NEOPROXY_BINARY), "--config", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proxy_proc.stdin.write(config)
        proxy_proc.stdin.close()
        try:
            exit_code = proxy_proc.wait(timeout=5.0)
            assert exit_code != 0, \
                f"Expected non-zero exit code for empty addresses, got {exit_code}"
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
            raise AssertionError("Process should have exited")

    def test_invalid_address_format(self) -> None:
        """
        TC-CFG-008: Address in listener is invalid.

        Target: Verify neoproxy reports invalid address error
        """
        config = """server_threads: 1

plugins:
  echo:

listeners:
- name: http_main
  kind: http
  addresses: ["invalid:address:format"]

services:
- name: echo
  kind: echo.echo

servers:
- name: test_server
  hostnames: []
  listeners: ["http_main"]
  service: echo
"""
        returncode, _, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "invalid address" in stderr, \
            f"Expected 'invalid address' in error, got: {stderr}"


    def test_unknown_field_in_socks5_args(self) -> None:
        """
        TC-S5-031: Unknown field in SOCKS5 listener args is rejected.

        Target: Verify proxy fails to start when SOCKS5 args contain
        an unknown field (serde deny_unknown_fields).
        """
        proxy_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks5_main
  kind: socks5
  addresses:
    - "0.0.0.0:{proxy_port}"
  args:
    some_unknown_field: true

servers:
- name: socks5_server
  listeners: ["socks5_main"]
  service: direct
"""
        proxy_proc = subprocess.Popen(
            [os.path.abspath(NEOPROXY_BINARY), "--config", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proxy_proc.stdin.write(config)
        proxy_proc.stdin.close()
        try:
            exit_code = proxy_proc.wait(timeout=5.0)
            assert exit_code != 0, \
                f"Expected non-zero exit code for unknown field, got {exit_code}"
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
            raise AssertionError("Process should have exited")

    def test_unknown_field_ca_path_in_service(self) -> None:
        """
        TC-CERT-REFACTOR-007: Unknown field at service level is rejected.

        After refactoring, http_upstream.upstream rejects ca_path at service
        level because the struct uses #[serde(deny_unknown_fields)].
        """
        config = """server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: test

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:30589"]

services:
- name: upstream
  kind: http_upstream.upstream
  args:
    upstream: test
    ca_path: "/tmp/ca.pem"

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: upstream
"""
        proxy_proc = subprocess.Popen(
            [os.path.abspath(NEOPROXY_BINARY), "--config", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proxy_proc.stdin.write(config)
        proxy_proc.stdin.close()
        try:
            exit_code = proxy_proc.wait(timeout=5.0)
            assert exit_code != 0, \
                f"Expected non-zero exit code for unknown field ca_path, got {exit_code}"
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
            raise AssertionError("Process should have exited")

    def test_invalid_handshake_timeout_format(self) -> None:
        """
        TC-S5-032: Invalid handshake timeout format in SOCKS5 listener.

        Target: Verify proxy fails to start with invalid timeout string.
        """
        proxy_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks5_main
  kind: socks5
  addresses:
    - "0.0.0.0:{proxy_port}"
  args:
    handshake_timeout: "invalid"

servers:
- name: socks5_server
  listeners: ["socks5_main"]
  service: direct
"""
        proxy_proc = subprocess.Popen(
            [os.path.abspath(NEOPROXY_BINARY), "--config", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proxy_proc.stdin.write(config)
        proxy_proc.stdin.close()
        try:
            exit_code = proxy_proc.wait(timeout=5.0)
            assert exit_code != 0, \
                f"Expected non-zero exit code for invalid timeout format, got {exit_code}"
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
            raise AssertionError("Process should have exited")

    def test_client_ca_path_rejected_in_socks5(self) -> None:
        """
        TC-S5-040 / TC-NEW-AUTH-006: client_ca_path rejected in SOCKS5 args.

        SOCKS5 protocol only supports password auth, not TLS client cert auth.
        client_ca_path is an unknown field in SOCKS5 args (deny_unknown_fields).
        """
        proxy_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks5_main
  kind: socks5
  addresses:
    - "0.0.0.0:{proxy_port}"
  args:
    client_ca_path: "/path/to/ca.pem"

servers:
- name: socks5_server
  listeners: ["socks5_main"]
  service: direct
"""
        proxy_proc = subprocess.Popen(
            [os.path.abspath(NEOPROXY_BINARY), "--config", "/dev/stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proxy_proc.stdin.write(config)
        proxy_proc.stdin.close()
        try:
            exit_code = proxy_proc.wait(timeout=5.0)
            assert exit_code != 0, \
                f"Expected non-zero exit code for client_ca_path in SOCKS5, got {exit_code}"
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
            proxy_proc.wait()
            raise AssertionError("Process should have exited")



# ==============================================================================
# Test cases - Hostname routing validation
# ==============================================================================


class TestHostnameRouting:
    """Hostname conflict and routing compatibility validation."""

    @staticmethod
    def _write_config(config_content: str) -> str:
        temp_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        )
        temp_file.write(config_content)
        temp_file.close()
        return temp_file.name

    def test_socks5_hostnames_rejected(self) -> None:
        """
        TC-HOST-001: SOCKS5 listener with hostnames should return error.

        SOCKS5 protocol does not support hostname routing.
        """
        socks_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  echo:

services:
- name: echo
  kind: echo.echo

listeners:
- name: socks_main
  kind: socks5
  addresses: ["127.0.0.1:{socks_port}"]

servers:
- name: socks_server
  hostnames: ["api.example.com"]
  listeners: ["socks_main"]
  service: echo
"""
        returncode, _, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "does not support hostname routing" in stderr, \
            f"Expected hostname routing compatibility error, got: {stderr}"

    def test_exact_hostname_duplicate(self) -> None:
        """
        TC-HOST-003: Exact hostname duplicate on same address should return error.
        """
        http_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  echo:

services:
- name: echo
  kind: echo.echo

listeners:
- name: http_a
  kind: http
  addresses: ["127.0.0.1:{http_port}"]
- name: http_b
  kind: http
  addresses: ["127.0.0.1:{http_port}"]

servers:
- name: server_a
  hostnames: ["api.example.com"]
  listeners: ["http_a"]
  service: echo
- name: server_b
  hostnames: ["api.example.com"]
  listeners: ["http_b"]
  service: echo
"""
        returncode, _, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "'api.example.com' defined in multiple servers" in stderr, \
            f"Expected hostname conflict error, got: {stderr}"

    def test_hostname_case_insensitive_conflict(self) -> None:
        """
        TC-HOST-004: Same hostname different case should return error.

        DNS is case-insensitive, so API.EXAMPLE.COM and api.example.com
        should be treated as the same hostname.
        """
        http_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  echo:

services:
- name: echo
  kind: echo.echo

listeners:
- name: http_a
  kind: http
  addresses: ["127.0.0.1:{http_port}"]
- name: http_b
  kind: http
  addresses: ["127.0.0.1:{http_port}"]

servers:
- name: server_a
  hostnames: ["API.EXAMPLE.COM"]
  listeners: ["http_a"]
  service: echo
- name: server_b
  hostnames: ["api.example.com"]
  listeners: ["http_b"]
  service: echo
"""
        returncode, _, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "'api.example.com' defined in multiple servers" in stderr, \
            f"Expected case-insensitive hostname conflict error, got: {stderr}"

    def test_wildcard_hostname_duplicate(self) -> None:
        """
        TC-HOST-005: Same wildcard on same address should return error.
        """
        http_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  echo:

services:
- name: echo
  kind: echo.echo

listeners:
- name: http_a
  kind: http
  addresses: ["127.0.0.1:{http_port}"]
- name: http_b
  kind: http
  addresses: ["127.0.0.1:{http_port}"]

servers:
- name: server_a
  hostnames: ["*.example.com"]
  listeners: ["http_a"]
  service: echo
- name: server_b
  hostnames: ["*.example.com"]
  listeners: ["http_b"]
  service: echo
"""
        returncode, _, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "'*.example.com' defined in multiple servers" in stderr, \
            f"Expected wildcard conflict error, got: {stderr}"

    def test_multiple_default_servers_same_address(self) -> None:
        """
        TC-HOST-007: Multiple SOCKS5 servers on same address should return error.

        SOCKS5 servers are treated as default servers (no hostname routing).
        Multiple default servers on the same address is a conflict.
        """
        socks_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks_a_main
  kind: socks5
  addresses: ["127.0.0.1:{socks_port}"]
- name: socks_b_main
  kind: socks5
  addresses: ["127.0.0.1:{socks_port}"]

servers:
- name: socks_a
  hostnames: []
  listeners: ["socks_a_main"]
  service: direct
- name: socks_b
  hostnames: []
  listeners: ["socks_b_main"]
  service: direct
"""
        returncode, _, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "without hostname routing support" in stderr, \
            f"Expected 'without hostname routing support' error, got: {stderr}"

    def test_socks5_without_hostnames_ok(self) -> None:
        """
        TC-HOST-002: SOCKS5 listener without hostnames should be valid.

        SOCKS5 with empty hostnames is valid and treated as a default server.
        """
        socks_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: socks_main
  kind: socks5
  addresses: ["127.0.0.1:{socks_port}"]

servers:
- name: socks_server
  hostnames: []
  listeners: ["socks_main"]
  service: direct
"""
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", self._write_config(config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            running = wait_for_process_running(proc, timeout=1.0)
            assert running, "SOCKS5 without hostnames should start successfully"
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

    def test_wildcard_and_exact_no_conflict(self) -> None:
        """
        TC-HOST-006: Wildcard and exact hostname on same address is valid.

        A wildcard (*.example.com) and an exact match (api.example.com)
        on the same address is NOT a conflict — exact match takes precedence.
        """
        http_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  echo:

services:
- name: echo
  kind: echo.echo

listeners:
- name: http_wildcard
  kind: http
  addresses: ["127.0.0.1:{http_port}"]
- name: http_specific
  kind: http
  addresses: ["127.0.0.1:{http_port}"]

servers:
- name: wildcard
  hostnames: ["*.example.com"]
  listeners: ["http_wildcard"]
  service: echo
- name: specific
  hostnames: ["api.example.com"]
  listeners: ["http_specific"]
  service: echo
"""
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", self._write_config(config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            running = wait_for_process_running(proc, timeout=1.0)
            assert running, "Wildcard + exact hostname should not conflict"
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)

    def test_different_hostnames_no_conflict(self) -> None:
        """
        TC-HOST-008: Different hostnames on same address is valid.

        Multiple servers with different hostnames on the same address
        is NOT a conflict — this is the intended use for hostname routing.
        """
        http_port = get_unique_port()
        config = f"""server_threads: 1

plugins:
  echo:

services:
- name: echo
  kind: echo.echo

listeners:
- name: http_a
  kind: http
  addresses: ["127.0.0.1:{http_port}"]
- name: http_b
  kind: http
  addresses: ["127.0.0.1:{http_port}"]

servers:
- name: server_a
  hostnames: ["api.example.com"]
  listeners: ["http_a"]
  service: echo
- name: server_b
  hostnames: ["web.example.com"]
  listeners: ["http_b"]
  service: echo
"""
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", self._write_config(config)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            running = wait_for_process_running(proc, timeout=1.0)
            assert running, "Different hostnames should not conflict"
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
