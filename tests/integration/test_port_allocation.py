"""
Test for port allocation in conftest.py.

These tests verify that the get_unique_port() function correctly allocates
ports that are actually available for binding.
"""

import socket
import subprocess
import tempfile
import shutil
from typing import Optional

import pytest

# Import from conftest
from .conftest import get_unique_port
from .utils.helpers import (
    create_test_config,
    start_proxy,
    wait_for_proxy,
    terminate_process,
)


class TestPortAllocation:
    """Test port allocation behavior."""

    def test_get_unique_port_returns_available_port(self) -> None:
        """
        Test that get_unique_port returns a port that can be bound.

        This test verifies the fix for CR-001: flaky integration tests
        due to port conflicts. The get_unique_port() function should
        return ports that are actually available for binding.
        """
        port = get_unique_port()

        # Try to bind to the port to verify it's available
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            # If we got here, the port is available
            assert True
        except OSError as e:
            pytest.fail(f"Port {port} returned by get_unique_port() is not available: {e}")
        finally:
            sock.close()

    def test_consecutive_ports_are_different(self) -> None:
        """
        Test that consecutive calls to get_unique_port return different ports.
        """
        ports = [get_unique_port() for _ in range(10)]
        assert len(ports) == len(set(ports)), "Consecutive ports should be unique"

    def test_port_can_be_used_for_proxy(self) -> None:
        """
        Test that the port returned by get_unique_port can be used to start a proxy.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            port = get_unique_port()
            config_path = create_test_config(port, temp_dir)
            proxy_proc = start_proxy(config_path)

            # Wait for proxy to be ready
            assert wait_for_proxy("127.0.0.1", port, timeout=5.0), \
                f"Proxy failed to start on port {port}"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_multiple_ports_can_be_used_concurrently(self) -> None:
        """
        Test that multiple ports can be allocated and used concurrently.
        """
        ports = [get_unique_port() for _ in range(5)]
        sockets = []

        try:
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", port))
                sock.listen(1)
                sockets.append(sock)

            # All ports should be bound successfully
            assert len(sockets) == 5

        finally:
            for sock in sockets:
                sock.close()
