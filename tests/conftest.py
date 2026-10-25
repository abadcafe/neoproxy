"""Configure the complete NeoProxy validation suite."""

import sys

import pytest

from tests.fixtures.binary import (
    NEOPROXY_BINARY,
    build_neoproxy_binary,
    check_binary_exists,
)


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers and check binary exists."""
    build_neoproxy_binary()
    if not check_binary_exists():
        print(
            (
                f"\nERROR: neoproxy binary not found at {NEOPROXY_BINARY}\n"
                + "Please run 'cargo build' or set NEOPROXY_BINARY.\n"
            ),
            file=sys.stderr,
        )
        sys.exit(1)

    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Add default markers to integration tests."""
    for item in items:
        # Mark all tests in integration directory as integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


pytest_plugins = [
    "tests.fixtures.listener_scenario",
    "tests.fixtures.access_log_scenario",
]
