"""module: http_configuration; responsibility: http configuration fixtures.
Public operations: create_test_config, create_echo_config, create_invalid_config.
Tests: sibling module tests and public fixture consumers.
"""

import os


def create_test_config(proxy_port: int, temp_dir: str, server_threads: int = 1) -> str:
    """
    Create test configuration file for direct upstream service.

    Args:
        proxy_port: Port for the proxy server
        temp_dir: Temporary directory for logs
        server_threads: Number of server threads

    Returns:
        str: Path to the configuration file
    """
    config_content = f"""server_threads: {server_threads}

plugins:
  upstream:
    upstreams:
      - name: direct

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: direct
  kind: upstream.upstream
  args:
    upstream: direct

servers:
- name: http_connect
  hostnames: []
  listeners: ["http_main"]
  service: direct
"""
    config_path = os.path.join(temp_dir, "test_config.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_echo_config(proxy_port: int, temp_dir: str, server_threads: int = 1) -> str:
    """
    Create echo service configuration file.

    Args:
        proxy_port: Port for the proxy server
        temp_dir: Temporary directory for logs
        server_threads: Number of server threads

    Returns:
        str: Path to the configuration file
    """
    config_content = f"""server_threads: {server_threads}

plugins:
  echo:

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{proxy_port}"]

services:
- name: echo
  kind: echo.echo

servers:
- name: echo_server
  hostnames: []
  listeners: ["http_main"]
  service: echo
"""
    config_path = os.path.join(temp_dir, "echo_config.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_invalid_config(temp_dir: str) -> str:
    """
    Create invalid YAML configuration file for testing error handling.

    Args:
        temp_dir: Temporary directory

    Returns:
        str: Path to the invalid configuration file
    """
    config_content = "server_threads: [\n  invalid yaml\n"
    config_path = os.path.join(temp_dir, "invalid.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path
