"""module: udp_sockets; responsibility: observe process-owned UDP bindings.
Public operations: bound_socket_count. Data entities: none.
Tests: HTTP/3 worker binding and shutdown process tests.
"""

from pathlib import Path

from tests.fixtures.proxy_process import BytesProcess


def bound_socket_count(process: BytesProcess, port: int) -> int:
    owned: set[str] = set()
    for descriptor in Path(f"/proc/{process.pid}/fd").iterdir():
        try:
            target = str(descriptor.readlink())
        except FileNotFoundError:
            # Other threads can finish an unrelated file operation
            # between listing descriptors and reading their links.
            continue
        if target.startswith("socket:["):
            owned.add(target[8:-1])
    bound: set[str] = set()
    for family in ("udp", "udp6"):
        table = Path(f"/proc/{process.pid}/net/{family}").read_text()
        for line in table.splitlines()[1:]:
            columns = line.split()
            if int(columns[1].split(":")[1], 16) == port and columns[9] in owned:
                bound.add(columns[9])
    return len(bound)
