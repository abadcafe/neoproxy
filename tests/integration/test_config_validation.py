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
    return f"""worker_threads: 1
log_directory: "/tmp/neoproxy_test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: default
  listeners:
  - kind: http
    addresses: [ "127.0.0.1:{proxy_port}" ]
    args:
      protocols: [ http ]
      hostnames: []
      certificates: []
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
worker_threads: [
  invalid yaml
services: []
"""

        returncode, stdout, stderr = run_neoproxy_with_config(invalid_yaml)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message indicates configuration error
        error_output = stderr
        assert "Configuration errors" in error_output or "parse" in error_output.lower(), \
            f"Expected YAML parse error in output, got: {error_output}"

    def test_config_invalid_service_kind_format(self) -> None:
        """
        TC-CFG-003: Service kind has invalid format (missing dot).

        Target: Verify neoproxy reports invalid kind format error
        """
        config = """worker_threads: 1
log_directory: "/tmp/test_logs"

services:
- name: test_service
  kind: echo

servers: []
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message contains "invalid format"
        assert "invalid format" in stderr, \
            f"Expected 'invalid format' in error, got: {stderr}"

        # Verify error message mentions expected format
        assert "service_name" in stderr or "plugin_name" in stderr, \
            f"Expected format hint in error, got: {stderr}"

    def test_config_plugin_not_found(self) -> None:
        """
        TC-CFG-004: Plugin referenced in kind does not exist.

        Target: Verify neoproxy reports plugin not found error.
        Note: Only services referenced by servers are validated for
        plugin existence.
        """
        config = """worker_threads: 1
log_directory: "/tmp/test_logs"

services:
- name: test_service
  kind: unknown_plugin.echo

servers:
- name: test_server
  listeners: []
  service: test_service
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message contains "plugin ... not found"
        assert "plugin 'unknown_plugin' not found" in stderr, \
            f"Expected 'plugin not found' in error, got: {stderr}"

    def test_config_service_builder_not_found(self) -> None:
        """
        TC-CFG-005: Service builder referenced in kind does not exist.

        Target: Verify neoproxy reports service builder not found error.
        Note: Only services referenced by servers are validated for
        service builder existence.
        """
        config = """worker_threads: 1
log_directory: "/tmp/test_logs"

services:
- name: test_service
  kind: echo.unknown_service

servers:
- name: test_server
  listeners: []
  service: test_service
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message contains "service builder ... not found"
        assert "service builder 'unknown_service' not found" in stderr, \
            f"Expected 'service builder not found' in error, got: {stderr}"

    def test_config_listener_builder_not_found(self) -> None:
        """
        TC-CFG-006: Listener builder referenced in kind does not exist.

        Target: Verify neoproxy reports listener builder not found error
        """
        config = """worker_threads: 1
log_directory: "/tmp/test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: test_server
  listeners:
  - kind: hyper.unknown_listener
    addresses: ["127.0.0.1:18080"]
    args:
      protocols: []
      hostnames: []
  service: echo
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify error message contains "listener builder ... not found"
        # The error includes the full kind name (e.g., 'hyper.unknown_listener')
        assert "listener builder 'hyper.unknown_listener' not found" in stderr, \
            f"Expected 'listener builder not found' in error, got: {stderr}"

    def test_config_service_not_found(self) -> None:
        """
        TC-CFG-007: Service referenced in server.service does not exist.

        Target: Verify neoproxy reports service not found error
        """
        config = """worker_threads: 1
log_directory: "/tmp/test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: test_server
  listeners:
  - kind: http
    addresses: ["127.0.0.1:18080"]
    args:
      protocols: []
      hostnames: []
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
        TC-CFG-008: Address in listener args is invalid.

        Target: Verify neoproxy reports invalid address error
        """
        config = """worker_threads: 1
log_directory: "/tmp/test_logs"

services:
- name: echo
  kind: echo.echo

servers:
- name: test_server
  listeners:
  - kind: http
    addresses: ["invalid:address:format"]
    args:
      protocols: []
      hostnames: []
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
        TC-CFG-009: Multiple configuration errors are all reported.

        Target: Verify neoproxy reports all errors at once.
        Note: Config parser stops at first kind format error, so we use
        valid kind formats but reference non-existent plugins/services.
        Only services referenced by servers are validated.
        """
        config = """worker_threads: 1
log_directory: "/tmp/test_logs"

services:
- name: service1
  kind: nonexistent_plugin.nonexistent_service
- name: service2
  kind: echo.nonexistent_service

servers:
- name: server1
  listeners: []
  service: service1
- name: server2
  listeners: []
  service: service2
"""
        returncode, stdout, stderr = run_neoproxy_with_config(config)

        # Verify exit code is 1
        assert returncode == 1, \
            f"Expected exit code 1, got {returncode}"

        # Verify multiple errors are reported
        # Should have errors: plugin not found, service builder not found
        error_count = stderr.count("services[") + stderr.count("servers[")
        assert error_count >= 2, \
            f"Expected multiple errors to be reported, got: {stderr}"

        # Verify error count is shown
        assert "error" in stderr.lower(), \
            f"Expected error count summary, got: {stderr}"