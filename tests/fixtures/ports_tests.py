"""Public behavior tests for ports."""

import errno
import socket
import threading
import time
from unittest.mock import MagicMock, patch

from tests.fixtures.ports import wait_for_udp_port_bound


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

        def bind_later() -> None:
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
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket_factory = MagicMock(return_value=mock_sock)
            mock_socket.side_effect = mock_socket_factory

            # Simulate permission denied error
            mock_bind = MagicMock(
                side_effect=OSError(errno.EACCES, "Permission denied")
            )
            mock_sock.bind = mock_bind

            result = wait_for_udp_port_bound("127.0.0.1", 12345, timeout=0.5)
            # Should return False (timeout), not True (incorrectly treating as "port in
            # use")
            assert result is False

    def test_returns_false_for_address_not_available(self) -> None:
        """Should return False when OSError is EADDRNOTAVAIL (address not available).

        This tests CR-001: The function should only return True for EADDRINUSE,
        not for other OSErrors like address not available.
        """
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_socket_factory = MagicMock(return_value=mock_sock)
            mock_socket.side_effect = mock_socket_factory

            # Simulate address not available error
            mock_bind = MagicMock(
                side_effect=OSError(
                    errno.EADDRNOTAVAIL, "Cannot assign requested address"
                )
            )
            mock_sock.bind = mock_bind

            result = wait_for_udp_port_bound(
                "invalid.host.that.does.not.exist", 12345, timeout=0.5
            )
            # Should return False (timeout), not True (incorrectly treating as "port in
            # use")
            assert result is False
