"""Baseline black-box tests for module dependency refactoring.

These tests verify core proxy functionality that must be preserved
throughout the refactoring. They run against the compiled binary.
"""
import os
import subprocess
from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    terminate_process,
    wait_for_proxy,
)
from .conftest import get_unique_port


def test_http_proxy_basic_connect(temp_dir: str) -> None:
    """HTTP proxy can handle a basic CONNECT request."""
    port = get_unique_port()
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"
services:
- name: echo_svc
  kind: echo.echo

servers:
- name: server1
  listeners:
  - kind: http
    args:
      addresses: [ "127.0.0.1:{port}" ]
  service: echo_svc
"""
    config_path = os.path.join(temp_dir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)

    proc = start_proxy(config_path)
    try:
        assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
            f"Proxy did not start on port {port}"
        # Use curl through the proxy - echo service returns 200 OK
        result = subprocess.run(
            ["curl", "-x", f"http://127.0.0.1:{port}", "-s", "-o", "/dev/null",
             "-w", "%{http_code}", "http://example.com"],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, \
            f"curl failed with return code {result.returncode}"
        assert result.stdout.strip() == "200", \
            f"Expected HTTP 200, got {result.stdout.strip()}"
    finally:
        terminate_process(proc)


def test_config_validation_bad_kind(temp_dir: str) -> None:
    """Config validation rejects invalid kind format (missing dot)."""
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: test
  kind: invalidkind

servers: []
"""
    config_path = os.path.join(temp_dir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)

    result = subprocess.run(
        [NEOPROXY_BINARY, "--config", config_path],
        capture_output=True, text=True, timeout=5
    )
    assert result.returncode != 0


def test_config_validation_nonexistent_plugin_no_servers(temp_dir: str) -> None:
    """Config with nonexistent plugin but no servers referencing it starts OK.

    After refactoring, runtime validation (plugin/builder existence) is removed
    from config_validator. A service with a nonexistent plugin but no servers
    referencing it will start successfully because the plugin is never
    instantiated.
    """
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services:
- name: test
  kind: nonexistent.service

servers: []
"""
    config_path = os.path.join(temp_dir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)

    proc = subprocess.Popen(
        [NEOPROXY_BINARY, "--config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        proc.wait(timeout=3)
        # Exit code 0: no servers means nothing to instantiate
        assert proc.returncode == 0, \
            f"Expected exit code 0, got {proc.returncode}"
    except subprocess.TimeoutExpired:
        # Process waits for signal when no servers - this is expected
        # Verify the process was still alive (not crashed) before terminating
        assert proc.poll() is None, \
            "Process should still be running (waiting for signal)"
        terminate_process(proc)
        # After graceful termination, exit code should not be a panic (1)
        assert proc.returncode != 1, \
            f"Process panicked during shutdown (exit code 1)"
