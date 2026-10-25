"""module: http_scenario; responsibility: run configured HTTP proxy scenarios.
Public operations: running_proxy, ProxyContext, ProxyWithConfig.
Data entities: ProxyContext, ProxyWithConfig.
Tests: http_scenario_tests.py and integration/test_layers.py.
"""

import copy
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path

from .configuration import ConfigDict, JsonValue, dict_to_yaml
from .ports import get_unique_port, wait_for_proxy
from .proxy_process import BytesProcess, managed_processes


@dataclass(frozen=True)
class ProxyContext:
    process: BytesProcess
    port: int
    working_dir: str


type ProxyWithConfig = Callable[[ConfigDict], AbstractContextManager[ProxyContext]]


def _with_port(config: ConfigDict, port: int) -> ConfigDict:
    prepared = copy.deepcopy(config)
    listeners = prepared.get("listeners", [])
    assert isinstance(listeners, list)
    for listener in listeners:
        assert isinstance(listener, dict)
        addresses = listener.get("addresses", [])
        assert isinstance(addresses, list)
        resolved: list[JsonValue] = []
        for address in addresses:
            assert isinstance(address, str)
            resolved.append(address.replace("AUTO_PORT", str(port)))
        listener["addresses"] = resolved or [f"127.0.0.1:{port}"]
    return prepared


@contextmanager
def running_proxy(
    directory: Path, config: ConfigDict
) -> Generator[ProxyContext, None, None]:
    """Run an isolated HTTP proxy, leaving the caller's configuration untouched.

    Listener addresses may contain AUTO_PORT; absent or empty addresses
    use loopback. All processes and pipes are released on context exit,
    including failed startup or an exception in the caller.
    """
    directory.mkdir(parents=True, exist_ok=True)
    port = get_unique_port()
    path = directory / f"config_{port}.yaml"
    _ = path.write_text(dict_to_yaml(_with_port(config, port)))
    with managed_processes() as start:
        process = start(str(path))
        assert wait_for_proxy("127.0.0.1", port, timeout=2, proc=process), (
            f"Proxy did not start on port {port}"
        )
        yield ProxyContext(process, port, str(directory))
