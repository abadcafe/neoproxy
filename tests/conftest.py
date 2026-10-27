"""module: conftest; responsibility: configure full-suite execution.
Public operations: pytest_configure, pytest_collection_modifyitems,
pytest_xdist_auto_num_workers. Data entities: none.
Tests: conftest_tests.py and full-suite runs.
"""

import os

import pytest

from tests.fixtures.binary import (
    NEOPROXY_BINARY,
    check_binary_exists,
)
from tests.fixtures.curl_capability import check_http3_proxy


def pytest_xdist_auto_num_workers() -> int:
    """Use up to eight available CPUs for independent process scenarios."""
    return min(8, os.process_cpu_count() or 1)


def pytest_configure(config: pytest.Config) -> None:
    """Check the prebuilt artifact and curl before starting workers."""
    if "PYTEST_XDIST_WORKER" not in os.environ:
        failures: list[str] = []
        if not check_binary_exists():
            failures.append(f"NeoProxy artifact missing: {NEOPROXY_BINARY}")
        if (failure := check_http3_proxy()) is not None:
            failures.append(failure)
        if failures:
            pytest.exit("\n".join(failures), returncode=1)

    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Start declared slow cases early to overlap their waiting periods."""
    for item in items:
        # Mark all tests in integration directory as integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
    items.sort(key=lambda item: item.get_closest_marker("slow") is None)


pytest_plugins = [
    "tests.fixtures.listener_scenario",
    "tests.fixtures.access_log_scenario",
]
