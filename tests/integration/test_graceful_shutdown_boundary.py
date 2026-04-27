"""
Graceful shutdown boundary conditions integration tests.

Test target: Verify neoproxy graceful shutdown boundary conditions
Test nature: Black-box testing through external interface (signals, process exit codes)

This test module covers:
- 7.1 Normal shutdown with no services/servers (boundary condition)
- Additional edge cases for graceful shutdown
"""

import subprocess
import socket
import threading
import tempfile
import shutil
import time
import os
import signal
from typing import Optional, Tuple, List, Callable

from .utils.helpers import (
    NEOPROXY_BINARY,
    LISTENER_SHUTDOWN_TIMEOUT,
    SERVICE_SHUTDOWN_TIMEOUT,
    MAX_SHUTDOWN_TIME,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    create_test_config,
)
from .conftest import get_unique_port


# ==============================================================================
# Test helper functions (unique to this module)
# ==============================================================================


def create_empty_config(temp_dir: str) -> str:
    """
    Create configuration file with no services or servers.

    This creates a minimal config with worker_threads: 1 (minimum allowed)
    and no services or servers. The process should still be able to
    handle signals and exit gracefully.

    Args:
        temp_dir: Temporary directory for logs

    Returns:
        str: Path to the configuration file
    """
    config_content = f"""worker_threads: 1
log_directory: "{temp_dir}/logs"

services: []

servers: []
"""
    config_path = os.path.join(temp_dir, "empty_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


# ==============================================================================
# Test cases - Boundary conditions
# ==============================================================================


class TestBoundaryConditions:
    """Test boundary conditions for graceful shutdown."""

    def test_empty_config_shutdown(self) -> None:
        """
        TC-BOUNDARY-001: Empty config shutdown should be immediate.

        Target: Verify that with worker_threads: 1 and no services/servers,
        the process:
        1. Starts successfully
        2. Waits for signals
        3. Exits immediately with code 0 when signaled

        This is a boundary condition test: minimal configuration with no
        active listeners, so shutdown should be near-instant.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_empty_config(temp_dir)
            proxy_proc = start_proxy(config_path)

            # Wait a moment for process to start
            time.sleep(0.5)

            # Verify process is running
            assert proxy_proc.poll() is None, \
                "Process should be running with no worker threads"

            # Record start time
            start_time = time.time()

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=5.0)
                elapsed = time.time() - start_time
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, \
                    "Process did not exit within expected time (no worker threads)"

            # Verify exit code is 0
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

            # Verify exit was fast (should be almost immediate)
            assert elapsed < 1.0, \
                f"Process should exit immediately, took {elapsed:.2f}s"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_empty_config_sigint(self) -> None:
        """
        TC-BOUNDARY-002: Empty config - SIGINT handling.

        Target: Verify SIGINT works the same as SIGTERM for empty config
        (worker_threads: 1, no services/servers).
        """
        temp_dir = tempfile.mkdtemp()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_empty_config(temp_dir)
            proxy_proc = start_proxy(config_path)

            # Wait a moment for process to start
            time.sleep(0.5)

            # Send SIGINT
            proxy_proc.send_signal(signal.SIGINT)

            # Wait for process to exit
            try:
                return_code = proxy_proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
                proxy_proc.wait()
                assert False, \
                    "Process did not exit within expected time"

            # Verify exit code is 0
            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - Shutdown timing verification
# ==============================================================================


class TestShutdownTiming:
    """Test shutdown timing behavior."""

    def test_shutdown_timing_normal_case(self) -> None:
        """
        TC-TIMING-001: Normal shutdown completes quickly.

        Target: Verify that shutdown with no active connections
        completes quickly (well within the timeout period)
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            start_time = time.time()
            proxy_proc.send_signal(signal.SIGTERM)

            return_code = proxy_proc.wait(timeout=10)
            elapsed = time.time() - start_time

            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

            # Normal shutdown should complete quickly
            assert elapsed < 2.0, \
                f"Normal shutdown should be fast, took {elapsed:.2f}s"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)


# ==============================================================================
# Test cases - Log verification
# ==============================================================================


class TestLogVerification:
    """Test that logs are properly generated during shutdown."""

    def test_shutdown_log_created(self) -> None:
        """
        TC-LOG-001: Verify shutdown log file is created.

        Target: Verify that log files are created in the specified directory
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            config_path = create_test_config(proxy_port, temp_dir)
            proxy_proc = start_proxy(config_path)

            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # Send SIGTERM
            proxy_proc.send_signal(signal.SIGTERM)

            # Wait for process to exit
            return_code = proxy_proc.wait(timeout=10)

            assert return_code == 0, \
                f"Expected exit code 0, got {return_code}"

            # Wait a moment for logs to be flushed
            time.sleep(0.5)

            # Check log directory exists
            log_dir = os.path.join(temp_dir, "logs")
            assert os.path.exists(log_dir), \
                f"Log directory should exist: {log_dir}"

            # Check for log files
            log_files = os.listdir(log_dir)
            assert len(log_files) > 0, \
                "Log files should be created"

            # Read log content
            log_content = ""
            for log_file in log_files:
                log_path = os.path.join(log_dir, log_file)
                with open(log_path, "r", errors="ignore") as f:
                    log_content += f.read()

            # Verify log contains expected keywords
            # The log should contain server start info
            assert "server" in log_content.lower() or "started" in log_content.lower(), \
                "Log should contain server start information"

        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)