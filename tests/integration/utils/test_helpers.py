"""
Unit tests for helper functions.
"""

import errno
import socket
import tempfile
import threading
import time
import os
from unittest.mock import patch, MagicMock

import pytest

from .helpers import wait_for_udp_port_bound, wait_for_log_contains


class TestWaitForUdpPortBound:
    """Tests for wait_for_udp_port_bound function."""

    def test_returns_true_when_port_is_bound(self) -> None:
        """Should return True when a UDP port is bound by another process."""
        port = 54321
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))

        try:
            result = wait_for_udp_port_bound("127.0.0.1", port, timeout=1.0)
            assert result is True
        finally:
            sock.close()

    def test_returns_false_when_port_not_bound(self) -> None:
        """Should return False when port is never bound within timeout."""
        # Use a port that's unlikely to be bound
        port = 59999
        result = wait_for_udp_port_bound("127.0.0.1", port, timeout=0.5)
        assert result is False

    def test_detects_port_bound_during_wait(self) -> None:
        """Should detect port becoming bound during the wait period."""
        port = 54322
        bound_event = threading.Event()

        def bind_later():
            time.sleep(0.2)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", port))
            bound_event.set()
            # Keep socket open until test completes
            time.sleep(2)
            sock.close()

        thread = threading.Thread(target=bind_later, daemon=True)
        thread.start()

        result = wait_for_udp_port_bound("127.0.0.1", port, timeout=2.0)
        assert result is True
        assert bound_event.is_set()

    def test_returns_false_for_permission_denied(self) -> None:
        """Should return False (not True) when OSError is EACCES (permission denied).

        This tests CR-001: The function should only return True for EADDRINUSE,
        not for other OSErrors like permission denied.
        """
        from . import helpers
        with patch.object(helpers, 'socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.socket.return_value = mock_sock

            # Simulate permission denied error
            mock_sock.bind.side_effect = OSError(errno.EACCES, "Permission denied")

            result = wait_for_udp_port_bound("127.0.0.1", 12345, timeout=0.5)
            # Should return False (timeout), not True (incorrectly treating as "port in use")
            assert result is False

    def test_returns_false_for_address_not_available(self) -> None:
        """Should return False when OSError is EADDRNOTAVAIL (address not available).

        This tests CR-001: The function should only return True for EADDRINUSE,
        not for other OSErrors like address not available.
        """
        from . import helpers
        with patch.object(helpers, 'socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.socket.return_value = mock_sock

            # Simulate address not available error
            mock_sock.bind.side_effect = OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

            result = wait_for_udp_port_bound("invalid.host.that.does.not.exist", 12345, timeout=0.5)
            # Should return False (timeout), not True (incorrectly treating as "port in use")
            assert result is False


class TestWaitForLogContains:
    """Tests for wait_for_log_contains function."""

    def test_returns_true_when_pattern_exists(self) -> None:
        """Should return True when pattern exists in log file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Server started\nListening on port 8080\n")
            log_path = f.name

        try:
            result = wait_for_log_contains(log_path, "Listening", timeout=1.0)
            assert result is True
        finally:
            os.unlink(log_path)

    def test_returns_false_when_pattern_not_found(self) -> None:
        """Should return False when pattern is never found within timeout."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Server started\n")
            log_path = f.name

        try:
            result = wait_for_log_contains(log_path, "ERROR", timeout=0.5)
            assert result is False
        finally:
            os.unlink(log_path)

    def test_detects_pattern_written_during_wait(self) -> None:
        """Should detect pattern written to log during the wait period."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Server starting...\n")
            log_path = f.name

        written_event = threading.Event()

        def write_later():
            time.sleep(0.2)
            with open(log_path, 'a') as f:
                f.write("READY: Server is ready\n")
            written_event.set()

        thread = threading.Thread(target=write_later, daemon=True)
        thread.start()

        try:
            result = wait_for_log_contains(log_path, "READY:", timeout=2.0)
            assert result is True
            assert written_event.is_set()
        finally:
            os.unlink(log_path)

    def test_returns_false_when_file_does_not_exist(self) -> None:
        """Should return False when log file does not exist."""
        result = wait_for_log_contains("/nonexistent/path/to/log.txt", "anything", timeout=0.5)
        assert result is False


class TestWaitForMetricValue:
    """Tests for wait_for_metric_value function."""

    def test_returns_true_when_metric_matches(self) -> None:
        """Should return True when metric value matches expected."""
        from .helpers import wait_for_metric_value

        call_count = 0

        def mock_fetch() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return "metric_value 0"
            return "metric_value 5"

        result = wait_for_metric_value(mock_fetch, "metric_value 5", timeout=2.0)
        assert result is True

    def test_returns_false_on_timeout(self) -> None:
        """Should return False when value never matches within timeout."""
        from .helpers import wait_for_metric_value

        def mock_fetch() -> str:
            return "metric_value 0"

        result = wait_for_metric_value(mock_fetch, "metric_value 999", timeout=0.5)
        assert result is False

    def test_returns_true_immediately_when_already_matches(self) -> None:
        """Should return True immediately when value already matches."""
        from .helpers import wait_for_metric_value

        def mock_fetch() -> str:
            return "metric_value 5"

        result = wait_for_metric_value(mock_fetch, "metric_value 5", timeout=0.5)
        assert result is True

    def test_handles_exception_gracefully(self) -> None:
        """Should handle exceptions from fetch function and continue polling."""
        from .helpers import wait_for_metric_value

        call_count = 0

        def mock_fetch() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("Connection error")
            return "metric_value 5"

        result = wait_for_metric_value(mock_fetch, "metric_value 5", timeout=2.0)
        assert result is True
