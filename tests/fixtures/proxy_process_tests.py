"""Public lifecycle behavior of a managed proxy process factory."""

import resource
from pathlib import Path

from tests.fixtures.http_configuration import create_echo_config, create_invalid_config
from tests.fixtures.ports import get_unique_port, wait_for_proxy
from tests.fixtures.proxy_process import (
    BytesProcess,
    managed_processes,
    start_proxy,
    terminate_process,
)


def assert_reaped(process: BytesProcess) -> None:
    assert process.poll() is not None
    assert process.stdout is not None and process.stdout.closed
    assert process.stderr is not None and process.stderr.closed


def test_managed_processes_reaps_all_children_and_closes_pipes(tmp_path: Path) -> None:
    with managed_processes() as start:
        processes: list[BytesProcess] = []
        for name in ["first", "second"]:
            directory = tmp_path / name
            directory.mkdir()
            port = get_unique_port()
            process = start(create_echo_config(port, str(directory)))
            processes.append(process)
            assert wait_for_proxy("127.0.0.1", port, timeout=2, proc=process)
        assert all(process.poll() is None for process in processes)
    for process in processes:
        assert_reaped(process)


def test_managed_processes_closes_pipes_of_already_exited_child(tmp_path: Path) -> None:
    with managed_processes() as start:
        process = start(create_invalid_config(str(tmp_path)))
        assert process.wait(timeout=2) == 1
    assert_reaped(process)


def test_start_proxy_limits_descriptors_without_changing_parent(tmp_path: Path) -> None:
    original = resource.getrlimit(resource.RLIMIT_NOFILE)
    port = get_unique_port()
    process = start_proxy(create_echo_config(port, str(tmp_path)), nofile_limit=64)
    try:
        assert wait_for_proxy("127.0.0.1", port, timeout=2, proc=process)
        assert resource.getrlimit(resource.RLIMIT_NOFILE) == original
    finally:
        terminate_process(process)
