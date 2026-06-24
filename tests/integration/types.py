import socket
import subprocess
from collections.abc import Callable, Generator
from contextlib import AbstractContextManager

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type ConfigDict = dict[str, JsonValue]
type StringMap = dict[str, str]
type BytesProcess = subprocess.Popen[bytes]
type TextProcess = subprocess.Popen[str]


class ProxyContext:
    def __init__(self, process: BytesProcess, port: int, working_dir: str) -> None:
        self.process = process
        self.port = port
        self.working_dir = working_dir


type ProxyWithConfig = Callable[[ConfigDict], AbstractContextManager[ProxyContext]]


class HttpServerInfo:
    def __init__(self, port: int, sock: socket.socket) -> None:
        self.port = port
        self.socket = sock
        self.url = f"http://127.0.0.1:{port}"


type TargetHttpServerFactory = Callable[[], AbstractContextManager[HttpServerInfo]]

type ProcessFactory = Callable[[str, int | None], BytesProcess]
type TargetHandler = Callable[[socket.socket], None]
type TargetServerFactory = Callable[[int, TargetHandler], socket.socket]
type IdleConnectionFactory = Callable[[str, int], socket.socket]
type PortFactory = Callable[[], int]
type WaitReady = Callable[[str, int, float], bool]
type FixtureGenerator[T] = Generator[T, None, None]
