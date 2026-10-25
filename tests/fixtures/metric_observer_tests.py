"""Public behavior tests for metric_observer."""


class TestWaitForMetricValue:
    """Tests for wait_for_metric_value function."""

    def test_returns_true_when_metric_matches(self) -> None:
        """Should return True when metric value matches expected."""
        from tests.fixtures.metric_observer import wait_for_metric_value

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
        from tests.fixtures.metric_observer import wait_for_metric_value

        def mock_fetch() -> str:
            return "metric_value 0"

        result = wait_for_metric_value(mock_fetch, "metric_value 999", timeout=0.5)
        assert result is False

    def test_returns_true_immediately_when_already_matches(
        self,
    ) -> None:
        """Should return True immediately when value already matches."""
        from tests.fixtures.metric_observer import wait_for_metric_value

        def mock_fetch() -> str:
            return "metric_value 5"

        result = wait_for_metric_value(mock_fetch, "metric_value 5", timeout=0.5)
        assert result is True

    def test_handles_exception_gracefully(self) -> None:
        """Should handle exceptions from fetch function and continue polling."""
        from tests.fixtures.metric_observer import wait_for_metric_value

        call_count = 0

        def mock_fetch() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise OSError("Connection error")
            return "metric_value 5"

        result = wait_for_metric_value(mock_fetch, "metric_value 5", timeout=2.0)
        assert result is True
