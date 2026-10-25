"""module: binary; responsibility: binary fixtures.
Public operations: neoproxy_cargo_features, check_binary_exists,
build_neoproxy_binary.
Tests: sibling module tests and public fixture consumers.
"""

import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NEOPROXY_BINARY = os.environ.get(
    "NEOPROXY_BINARY", str(PROJECT_ROOT / "target" / "debug" / "neoproxy")
)
DEFAULT_CARGO_FEATURES = ""


def neoproxy_cargo_features() -> str:
    """Cargo features used for the integration-test binary build."""
    return os.environ.get("NEOPROXY_CARGO_FEATURES", DEFAULT_CARGO_FEATURES)


def check_binary_exists() -> bool:
    """
    Check if the neoproxy binary exists.

    Returns:
        bool: True if binary exists, False otherwise
    """
    return os.path.exists(NEOPROXY_BINARY)


def build_neoproxy_binary() -> None:
    """Build the neoproxy binary used by integration tests.

    If NEOPROXY_BINARY is set explicitly, tests use that path as-is and
    only verify it exists. Otherwise, build the default debug binary from
    the current workspace so tests cannot accidentally run a stale release
    artifact.
    """
    if "NEOPROXY_BINARY" in os.environ:
        return

    cmd = ["cargo", "build"]
    features = neoproxy_cargo_features()
    if features:
        cmd.extend(["--features", features])

    _ = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
