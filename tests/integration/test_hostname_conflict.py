"""
Hostname conflict detection black-box tests.

Test target: Verify neoproxy hostname conflict detection behavior
Test nature: Black-box testing through external interface (CLI)

This test file follows TDD: tests are written BEFORE implementation.
All tests should FAIL initially because the feature is not implemented.
"""

import subprocess
import tempfile
import os
import time
from typing import Tuple, Optional

import pytest

from .utils.helpers import NEOPROXY_BINARY
from .conftest import get_unique_port


def run_neoproxy_with_config(
    config_content: str,
    timeout: float = 5.0
) -> Tuple[int, str, str]:
    """
    Run neoproxy with a given configuration content and wait for it to exit.

    Use this for testing INVALID configurations that should fail at startup.

    Args:
        config_content: Configuration content to write to a temp file
        timeout: Timeout for the process to exit

    Returns:
        Tuple[int, str, str]: Return code, stdout, stderr
    """
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', suffix='.yaml', delete=False
    )
    temp_file.write(config_content)
    temp_file.close()

    try:
        result = subprocess.run(
            [NEOPROXY_BINARY, "--config", temp_file.name],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    finally:
        os.unlink(temp_file.name)


def start_neoproxy_and_check_running(
    config_content: str,
    startup_timeout: float = 1.0
) -> Tuple[Optional[subprocess.Popen], str, str]:
    """
    Start neoproxy as a background process and verify it starts successfully.

    Use this for testing VALID configurations that should run without errors.

    Args:
        config_content: Configuration content to write to a temp file
        startup_timeout: Time to wait for process to start and stay running

    Returns:
        Tuple[Optional[Popen], str, str]: Process handle (None if exited), stdout, stderr
    """
    temp_file = tempfile.NamedTemporaryFile(
        mode='w', suffix='.yaml', delete=False
    )
    temp_file.write(config_content)
    temp_file.close()

    proc = None
    stdout_data = ""
    stderr_data = ""

    try:
        proc = subprocess.Popen(
            [NEOPROXY_BINARY, "--config", temp_file.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait a short time and check if process is still running
        time.sleep(startup_timeout)

        if proc.poll() is not None:
            # Process exited, capture output
            stdout_data, stderr_data = proc.communicate()
            proc = None  # Return None to indicate process exited

        return proc, stdout_data, stderr_data
    finally:
        os.unlink(temp_file.name)


class TestSOCKS5HostnameValidation:
    """Test SOCKS5 + hostnames semantic validation."""

    def test_socks5_with_hostnames_returns_error(self) -> None:
        """
        TC-HOST-001: SOCKS5 listener with hostnames should return error.

        SOCKS5 protocol does not support hostname routing.
        Configuration with hostnames on SOCKS5 listener should fail.

        Expected: Exit code 1, error message about SOCKS5 + hostnames
        """
        socks_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: socks_server
  hostnames: ["api.example.com"]
  listeners:
  - kind: socks5
    addresses: ["127.0.0.1:{socks_port}"]
  service: echo
"""
        try:
            returncode, stdout, stderr = run_neoproxy_with_config(config)
            assert returncode == 1, \
                f"Expected exit code 1, got {returncode}"

            assert "does not support hostname routing" in stderr, \
                f"Expected hostname routing compatibility error in stderr, got: {stderr}"
        except subprocess.TimeoutExpired:
            # Feature not implemented - server started instead of failing
            pytest.fail(
                "TC-HOST-001: SOCKS5 + hostnames validation not implemented. "
                "Server started successfully instead of failing with validation error."
            )

    def test_socks5_without_hostnames_ok(self) -> None:
        """
        TC-HOST-002: SOCKS5 listener without hostnames should be valid.

        SOCKS5 with empty hostnames (or no hostnames field) is valid.
        SOCKS5 is treated as a default server.

        Expected: Process starts successfully and stays running.
        """
        socks_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: socks_server
  hostnames: []
  listeners:
  - kind: socks5
    addresses: ["127.0.0.1:{socks_port}"]
  service: connect_tcp
"""
        proc, stdout, stderr = start_neoproxy_and_check_running(config)
        try:
            if proc is None:
                # Process exited unexpectedly
                assert "does not support hostname routing" not in stderr, \
                    f"Should not have hostname routing error, got: {stderr}"
                pytest.fail(
                    f"Process exited unexpectedly with code. stderr: {stderr}"
                )
            # Process is running — valid config accepted
            assert "does not support hostname routing" not in stderr
        finally:
            if proc is not None:
                proc.terminate()
                proc.wait()


class TestExactHostnameConflict:
    """Test exact hostname duplicate detection."""

    def test_exact_hostname_duplicate_returns_error(self) -> None:
        """
        TC-HOST-003: Exact hostname duplicate on same address should return error.

        Two servers with the same hostname on the same address is a conflict.

        Expected: Exit code 1, error message about hostname conflict
        """
        http_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: server_a
  hostnames: ["api.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo

- name: server_b
  hostnames: ["api.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo
"""
        try:
            returncode, stdout, stderr = run_neoproxy_with_config(config)
            assert returncode == 1, \
                f"Expected exit code 1, got {returncode}"

            assert "'api.example.com' defined in multiple servers" in stderr, \
                f"Expected hostname conflict error in stderr, got: {stderr}"
        except subprocess.TimeoutExpired:
            # Feature not implemented - server started instead of failing
            pytest.fail(
                "TC-HOST-003: Exact hostname conflict detection not implemented. "
                "Server started successfully instead of failing with validation error."
            )

    def test_hostname_case_insensitive_conflict(self) -> None:
        """
        TC-HOST-004: Same hostname different case should return error.

        DNS is case-insensitive, so API.EXAMPLE.COM and api.example.com
        should be treated as the same hostname.

        Expected: Exit code 1, error message about hostname conflict
        """
        http_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: server_a
  hostnames: ["API.EXAMPLE.COM"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo

- name: server_b
  hostnames: ["api.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo
"""
        try:
            returncode, stdout, stderr = run_neoproxy_with_config(config)
            assert returncode == 1, \
                f"Expected exit code 1, got {returncode}"

            # Error should mention lowercase version (normalized)
            assert "'api.example.com' defined in multiple servers" in stderr, \
                f"Expected case-insensitive hostname conflict error in stderr, got: {stderr}"
        except subprocess.TimeoutExpired:
            # Feature not implemented - server started instead of failing
            pytest.fail(
                "TC-HOST-004: Case-insensitive hostname conflict detection not implemented. "
                "Server started successfully instead of failing with validation error."
            )


class TestWildcardHostnameConflict:
    """Test wildcard hostname duplicate detection."""

    def test_wildcard_duplicate_returns_error(self) -> None:
        """
        TC-HOST-005: Same wildcard on same address should return error.

        Two servers with the same wildcard pattern on the same address is a conflict.

        Expected: Exit code 1, error message about wildcard conflict
        """
        http_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: server_a
  hostnames: ["*.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo

- name: server_b
  hostnames: ["*.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo
"""
        try:
            returncode, stdout, stderr = run_neoproxy_with_config(config)
            assert returncode == 1, \
                f"Expected exit code 1, got {returncode}"

            assert "'*.example.com' defined in multiple servers" in stderr, \
                f"Expected wildcard conflict error in stderr, got: {stderr}"
        except subprocess.TimeoutExpired:
            # Feature not implemented - server started instead of failing
            pytest.fail(
                "TC-HOST-005: Wildcard conflict detection not implemented. "
                "Server started successfully instead of failing with validation error."
            )

    def test_wildcard_and_exact_no_conflict(self) -> None:
        """
        TC-HOST-006: Wildcard and exact hostname should be valid.

        A wildcard (*.example.com) and an exact match (api.example.com)
        on the same address is NOT a conflict - exact match takes precedence.

        Expected: Process starts successfully and stays running.
        """
        http_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: wildcard
  hostnames: ["*.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo

- name: specific
  hostnames: ["api.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo
"""
        proc, stdout, stderr = start_neoproxy_and_check_running(config)
        try:
            if proc is None:
                # Process exited unexpectedly
                assert "defined in multiple servers" not in stderr, \
                    f"Wildcard + exact should not be a conflict, got: {stderr}"
                pytest.fail(
                    f"Process exited unexpectedly. stderr: {stderr}"
                )
            # Process is running — valid config accepted
            assert "defined in multiple servers" not in stderr
        finally:
            if proc is not None:
                proc.terminate()
                proc.wait()


class TestMultipleSOCKS5Conflict:
    """Test multiple SOCKS5 servers on same address."""

    def test_multiple_socks5_same_address_returns_error(self) -> None:
        """
        TC-HOST-007: Multiple SOCKS5 on same address should return error.

        SOCKS5 servers are treated as default servers (no hostname routing).
        Multiple default servers on the same address is a conflict.

        Expected: Exit code 1, error message about multiple default servers
        """
        socks_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: connect_tcp
  kind: connect_tcp.connect_tcp

servers:
- name: socks_a
  hostnames: []
  listeners:
  - kind: socks5
    addresses: ["127.0.0.1:{socks_port}"]
  service: connect_tcp

- name: socks_b
  hostnames: []
  listeners:
  - kind: socks5
    addresses: ["127.0.0.1:{socks_port}"]
  service: connect_tcp
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        assert "without hostname routing support" in stderr, \
            f"Expected 'without hostname routing support' error in stderr, got: {stderr}"

        # Verify the error mentions both server names
        assert "socks_a" in stderr or "socks_b" in stderr, \
            f"Error should mention server names, got: {stderr}"


class TestDifferentHostnamesNoConflict:
    """Test that different hostnames on same address is valid."""

    def test_different_hostnames_no_conflict(self) -> None:
        """
        TC-HOST-008: Different hostnames on same address should be valid.

        Multiple servers with different hostnames on the same address is NOT a conflict.
        This is the intended use case for hostname-based routing.

        Expected: Process starts successfully and stays running.
        """
        http_port = get_unique_port()
        config = f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: server_a
  hostnames: ["api.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo

- name: server_b
  hostnames: ["web.example.com"]
  listeners:
  - kind: http
    addresses: ["127.0.0.1:{http_port}"]
  service: echo
"""
        proc, stdout, stderr = start_neoproxy_and_check_running(config)
        try:
            if proc is None:
                # Process exited unexpectedly
                assert "defined in multiple servers" not in stderr, \
                    f"Different hostnames should not be a conflict, got: {stderr}"
                pytest.fail(
                    f"Process exited unexpectedly. stderr: {stderr}"
                )
            # Process is running — valid config accepted
            assert "defined in multiple servers" not in stderr
        finally:
            if proc is not None:
                proc.terminate()
                proc.wait()
