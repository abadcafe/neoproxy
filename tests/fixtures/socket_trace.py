"""module: socket_trace; responsibility: persist kernel socket observations.
Public operations: SocketTrace context manager, watch; SocketSample artifact schema.
Data entities: SocketTrace, SocketSample.
Tests: socket_trace_tests.py.
"""

import os
import subprocess
import threading
import time
from pathlib import Path
from types import TracebackType
from typing import Literal, Self, TextIO

from pydantic import BaseModel


class SocketSample(BaseModel):
    timestamp_ns: int
    monotonic_ns: int
    protocol: Literal["tcp", "udp"]
    process_ids: list[int]
    returncode: int | None
    output: str
    error: str | None


class SocketTrace:
    """Sample watched PIDs every 250 ms; record collection errors explicitly."""

    def __init__(self, output: Path) -> None:
        self._path: Path = output
        self._pids: list[int] = []
        self._lock: threading.Lock = threading.Lock()
        self._stop: threading.Event = threading.Event()
        self._worker: threading.Thread = threading.Thread(
            target=self._run, name="chain-sockets"
        )
        self._output: TextIO | None = None

    def __enter__(self) -> Self:
        self._output = self._path.open("w")
        self._worker.start()
        return self

    def watch(self, pid: int) -> None:
        with self._lock:
            self._pids.append(pid)

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._worker.join()
        assert self._output is not None
        self._output.close()

    def _run(self) -> None:
        assert self._output is not None
        while True:
            with self._lock:
                pids = list(self._pids)
            for protocol in ("tcp", "udp"):
                sample = self._sample(protocol, pids)
                _ = self._output.write(sample.model_dump_json() + "\n")
                self._output.flush()
            if self._stop.wait(0.25):
                return

    def _sample(self, protocol: Literal["tcp", "udp"], pids: list[int]) -> SocketSample:
        sample = SocketSample(
            timestamp_ns=time.time_ns(),
            monotonic_ns=time.monotonic_ns(),
            protocol=protocol,
            process_ids=pids,
            returncode=0,
            output="",
            error=None,
        )
        if not pids:
            return sample
        try:
            result = subprocess.run(
                ["ss", "-tinap" if protocol == "tcp" else "-uinap"],
                capture_output=True,
                text=True,
                timeout=1,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            sample.returncode = None
            sample.error = str(error)
            return sample
        sample.returncode = result.returncode
        sample.error = result.stderr or None
        selected: list[str] = []
        owned = False
        for line in result.stdout.splitlines():
            if line and not line[0].isspace():
                owned = any(f"pid={pid}," in line for pid in pids)
            if owned:
                selected.append(line)
        sample.output = "\n".join(selected)
        return sample
