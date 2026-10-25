"""Public behavior tests for log_observer."""

import os
import tempfile
import threading
import time

from tests.fixtures.log_observer import wait_for_log_contains


class TestWaitForLogContains:
    """Tests for wait_for_log_contains function."""

    def test_returns_true_when_pattern_exists(self) -> None:
        """Should return True when pattern exists in log file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            _ = f.write("Server started\nListening on port 8080\n")
            log_path = f.name

        try:
            result = wait_for_log_contains(log_path, "Listening", timeout=1.0)
            assert result is True
        finally:
            os.unlink(log_path)

    def test_returns_false_when_pattern_not_found(self) -> None:
        """Should return False when pattern is never found within timeout."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            _ = f.write("Server started\n")
            log_path = f.name

        try:
            result = wait_for_log_contains(log_path, "ERROR", timeout=0.5)
            assert result is False
        finally:
            os.unlink(log_path)

    def test_detects_pattern_written_during_wait(self) -> None:
        """Should detect pattern written to log during the wait period."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            _ = f.write("Server starting...\n")
            log_path = f.name

        written_event = threading.Event()

        def write_later() -> None:
            time.sleep(0.2)
            with open(log_path, "a") as f:
                _ = f.write("READY: Server is ready\n")
                f.flush()
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
        result = wait_for_log_contains(
            "/nonexistent/path/to/log.txt", "anything", timeout=0.5
        )
        assert result is False
