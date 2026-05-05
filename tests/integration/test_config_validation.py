"""
Configuration validation integration tests.

Test target: Verify neoproxy configuration validation behavior
Test nature: Black-box testing through external interface (CLI)
"""

import subprocess
import tempfile
import os
from typing import Tuple, Optional

from .utils.helpers import NEOPROXY_BINARY
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


def create_valid_config(proxy_port: int = 18080) -> str:
    """
    Create a valid configuration content.

    Args:
        proxy_port: Port for the proxy server

    Returns:
        str: Valid YAML configuration
    """
    return f"""server_threads: 1

listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:{proxy_port}"]

services:
- name: echo
  kind: echo.echo

servers:
- name: default
  hostnames: []
  listeners: ["http_main"]
  service: echo
"""


# ==============================================================================
# Test cases
# ==============================================================================


class TestConfigValidation:
    """Configuration validation integration tests."""

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

        # Verify exit code is 1
        assert result.returncode == 1, \
            f"Expected exit code 1, got {result.returncode}"

        # Verify error message contains expected text
        stderr = result.stderr
        assert "read config file" in stderr, \
            f"Expected 'read config file' in error, got: {stderr}"

    def test_config_invalid_yaml(self) -> None:
        """
        TC-CFG-002: Configuration file has invalid YAML syntax.

        Target: Verify neoproxy reports YAML parsing error
        """
        # YAML with syntax error: unclosed bracket
        invalid_yaml = """
server_threads: [
  invalid yaml
services: []
"""

        returncode, stdout, stderr = run_neoproxy_with_config(invalid_yaml)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message indicates YAML parse error
        error_output = stderr.lower()
        assert "error" in error_output or "parse" in error_output or "expected" in error_output, \
            f"Expected YAML parse error in output, got: {stderr}"

    def test_config_invalid_service_kind_format(self) -> None:
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

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message contains invalid kind format
        assert "invalid service kind" in stderr or "expected 'plugin_name.service_name'" in stderr, \
            f"Expected invalid kind format error, got: {stderr}"

    def test_config_plugin_not_found(self) -> None:
        """
        TC-CFG-004: Plugin referenced in kind does not exist.

        Target: Verify neoproxy fails when plugin does not exist.
        Note: Plugin validation happens at runtime (building listeners),
        so exit code is 2 (error) not 1 (config validation).
        Runtime errors are logged to file, not stdout/stderr.
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
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify error occurs (exit code 1 or 2 - config or runtime error)
        assert returncode != 0, \
            f"Expected non-zero exit code, got {returncode}"

    def test_config_service_builder_not_found(self) -> None:
        """
        TC-CFG-005: Service builder referenced in kind does not exist.

        Target: Verify neoproxy fails when service builder does not exist.
        Note: Service builder validation happens at runtime, so exit
        code is 2 (error) not 1 (config validation).
        Runtime errors are logged to file, not stdout/stderr.
        """
        config = """server_threads: 1

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
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify error occurs (exit code 1 or 2)
        assert returncode != 0, \
            f"Expected non-zero exit code, got {returncode}"

    def test_config_listener_builder_not_found(self) -> None:
        """
        TC-CFG-006: Listener builder referenced in kind does not exist.

        Target: Verify neoproxy fails when listener builder does not exist.
        Note: Listener builder validation happens at runtime, so exit
        code is 2 (error) not 1 (config validation).
        Runtime errors are logged to file, not stdout/stderr.
        """
        config = """server_threads: 1

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
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify error occurs (exit code 1 or 2)
        assert returncode != 0, \
            f"Expected non-zero exit code, got {returncode}"

    def test_config_service_not_found(self) -> None:
        """
        TC-CFG-007: Service referenced in server.service does not exist.

        Target: Verify neoproxy reports service not found error
        """
        config = """server_threads: 1

listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:18080"]

services:
- name: echo
  kind: echo.echo

servers:
- name: test_server
  hostnames: []
  listeners: ["http_main"]
  service: nonexistent_service
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message contains "service ... not found"
        assert "service 'nonexistent_service' not found" in stderr, \
            f"Expected 'service not found' in error, got: {stderr}"

    def test_config_invalid_address(self) -> None:
        """
        TC-CFG-008: Address in listener is invalid.

        Target: Verify neoproxy reports invalid address error
        """
        config = """server_threads: 1

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
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message contains "invalid address"
        assert "invalid address" in stderr, \
            f"Expected 'invalid address' in error, got: {stderr}"

    def test_config_multiple_errors(self) -> None:
        """
        TC-CFG-009: Multiple configuration errors cause failure.

        Target: Verify neoproxy fails when multiple configuration errors exist.
        Uses two services with invalid kinds (missing dot) to trigger
        kind format errors. The proxy reports the first error and exits.
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
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1 (config validation error)
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message mentions invalid kind format
        assert "invalid service kind" in stderr or "expected 'plugin_name.service_name'" in stderr, \
            f"Expected kind format error, got: {stderr}"
