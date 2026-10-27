"""Process contracts for the example certificate generator's file ownership."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("generation_fails", [False, True])
def test_certificate_generator_preserves_unowned_files_and_failed_generation(
    tmp_path: Path, generation_fails: bool
) -> None:
    source = Path(__file__).resolve().parents[2] / "conf/certs/generate_certs.sh"
    script = tmp_path / "generate_certs.sh"
    _ = shutil.copyfile(source, script)
    unrelated = tmp_path / "unrelated.key"
    _ = unrelated.write_text("unrelated private key")
    existing = tmp_path / "server.key"
    _ = existing.write_text("previous server key")
    environment = dict(os.environ)
    if generation_fails:
        commands = tmp_path / "commands"
        commands.mkdir()
        openssl = commands / "openssl"
        _ = openssl.write_text("#!/bin/sh\nexit 1\n")
        openssl.chmod(0o700)
        environment["PATH"] = f"{commands}:{environment['PATH']}"
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, timeout=20, env=environment
    )
    assert unrelated.exists(), result.stderr
    assert unrelated.read_text() == "unrelated private key"
    if generation_fails:
        assert result.returncode != 0
        assert existing.read_text() == "previous server key"
    else:
        assert result.returncode == 0, result.stderr
        key = subprocess.run(
            ["openssl", "rsa", "-in", str(existing), "-noout", "-check"],
            capture_output=True,
            timeout=10,
            env=environment,
        )
        assert key.returncode == 0, key.stderr
        assert existing.stat().st_mode & 0o077 == 0
