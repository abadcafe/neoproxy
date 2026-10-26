"""module: chain_diagnostics; responsibility: own durable chain-test evidence.
Public operations: record_chain, ChainCapture.{directory,start_proxy,run_curl}.
Data entities: ChainCapture, ChainManifest.
Tests: chain_diagnostics_tests.py and existing proxy-chain integration cases.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Generator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import TracebackType
from typing import IO, Self

from pydantic import BaseModel, Field

from tests.fixtures.binary import NEOPROXY_BINARY, PROJECT_ROOT
from tests.fixtures.curl import get_curl_env_without_no_proxy
from tests.fixtures.proxy_process import BytesProcess, start_proxy, terminate_process
from tests.fixtures.socket_trace import SocketTrace

_LOG_FILTER = (
    "neoproxy=trace,hyper=debug,hyper_util=debug,h3=trace,quinn=debug,rustls=debug"
)
_METRICS_MARKER = "\nNEOPROXY_CURL_METRICS\n"


class ChainManifest(BaseModel):
    metadata: dict[str, str]
    pytest_case: str | None
    binary: str
    started_ns: int
    finished_ns: int | None = None
    failure: str | None = None
    source_directories: dict[str, str]
    processes: dict[str, int] = Field(default_factory=dict)
    exit_codes: dict[str, int | None] = Field(default_factory=dict)
    log_filter: str = _LOG_FILTER


class ChainCapture:
    def __init__(
        self,
        directory: Path,
        resources: ExitStack,
        sockets: SocketTrace,
        manifest: ChainManifest,
    ) -> None:
        self._directory: Path = directory
        self._resources: ExitStack = resources
        self._sockets: SocketTrace = sockets
        self._manifest: ChainManifest = manifest
        self._processes: list[tuple[str, BytesProcess]] = []

    @property
    def directory(self) -> Path:
        return self._directory

    def start_proxy(self, role: str, config: str) -> BytesProcess:
        """Drain both child pipes continuously and flush logs on shutdown."""
        destination = self.directory / role
        destination.mkdir(exist_ok=True)
        process = self._resources.enter_context(
            start_proxy(
                config,
                env={**os.environ, "NEOPROXY_LOG": _LOG_FILTER, "RUST_BACKTRACE": "1"},
            )
        )
        self._processes.append((role, process))
        self._manifest.processes[role] = process.pid
        _ = (self.directory / "manifest.json").write_text(
            self._manifest.model_dump_json(indent=2)
        )
        _ = shutil.copyfile(config, destination / Path(config).name)
        self._sockets.watch(process.pid)
        for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            assert pipe is not None
            output = self._resources.enter_context(
                (destination / f"{name}.log").open("wb")
            )
            worker = threading.Thread(
                target=self._drain, args=(pipe, output), name=f"chain-{role}-{name}"
            )
            worker.start()
            _ = self._resources.callback(worker.join)
        return process

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # Run before ExitStack joins readers, including setup failures.
        for role, process in reversed(self._processes):
            terminate_process(process)
            self._manifest.exit_codes[role] = process.poll()

    @staticmethod
    def _drain(pipe: IO[bytes], output: IO[bytes]) -> None:
        shutil.copyfileobj(pipe, output)
        output.flush()

    def run_curl(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Add observation only; return the original stdout and exit status."""
        observed = list(command)
        index = observed.index("--write-out") + 1
        observed[index] += _METRICS_MARKER + "%{json}"
        observed[1:1] = [
            "--trace-time",
            "--dump-header",
            str(self.directory / "curl.headers"),
        ]
        _ = (self.directory / "curl.command.json").write_text(
            json.dumps(observed, indent=2)
        )
        result = subprocess.run(
            observed,
            capture_output=True,
            text=True,
            timeout=25,
            env=get_curl_env_without_no_proxy(),
        )
        status, separator, metrics = result.stdout.partition(_METRICS_MARKER)
        _ = (self.directory / "curl.stdout").write_text(status)
        _ = (self.directory / "curl.stderr").write_text(result.stderr)
        if separator:
            _ = (self.directory / "curl.metrics.json").write_text(metrics)
        else:
            _ = (self.directory / "curl.metrics.error").write_text(
                f"curl exited with {result.returncode} before emitting metrics\n"
            )
        return subprocess.CompletedProcess(
            command, result.returncode, status, result.stderr
        )


@contextmanager
def record_chain(
    sources: Mapping[str, Path],
    metadata: Mapping[str, str],
    *,
    artifact_root: Path | None = None,
) -> Generator[ChainCapture, None, None]:
    """Keep evidence for every run, including failures before curl starts."""
    root = artifact_root or Path(
        os.environ.get(
            "NEOPROXY_TEST_ARTIFACTS",
            str(PROJECT_ROOT / "tmp/test-artifacts/proxy-chain"),
        )
    )
    root.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="chain-", dir=root)).resolve()
    manifest = ChainManifest(
        metadata=dict(metadata),
        pytest_case=os.environ.get("PYTEST_CURRENT_TEST"),
        binary=NEOPROXY_BINARY,
        started_ns=time.time_ns(),
        source_directories={
            role: str(path.resolve()) for role, path in sources.items()
        },
    )
    _ = (directory / "manifest.json").write_text(manifest.model_dump_json(indent=2))
    try:
        with ExitStack() as resources:
            sockets = resources.enter_context(SocketTrace(directory / "sockets.jsonl"))
            with ChainCapture(directory, resources, sockets, manifest) as capture:
                yield capture
    finally:
        failure = sys.exception()
        manifest.finished_ns = time.time_ns()
        if failure is not None:
            manifest.failure = f"{type(failure).__name__}: {failure}"
        for role, source in sources.items():
            for pattern in ("*.yaml", "curl.*", "logs/*"):
                for path in source.glob(pattern):
                    if path.is_file():
                        destination = directory / role / path.relative_to(source)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        _ = shutil.copyfile(path, destination)
        _ = (directory / "manifest.json").write_text(manifest.model_dump_json(indent=2))
        print(f"Proxy-chain diagnostics: {directory}", file=sys.stderr)
