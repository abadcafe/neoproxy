"""module: matrix_observation; responsibility: represent captured chain evidence.
Public operations/data: AccessEntry, OriginRequest, Exchange, read_access.
Tests: chain matrix integration tests.
"""

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from .configuration import JsonValue


class AccessEntry(BaseModel):
    method: str
    status: int
    target: str
    extensions: dict[str, JsonValue] = Field(default_factory=dict)


@dataclass(frozen=True)
class OriginRequest:
    method: str
    path: str
    body: bytes


@dataclass(frozen=True)
class Exchange:
    returncode: int
    http_status: int
    connect_status: int
    stderr: str
    body: bytes
    sent_body: bytes
    entry_logs: list[AccessEntry]
    relay_logs: list[AccessEntry]
    origin_requests: list[OriginRequest]


def read_access(directory: Path) -> list[AccessEntry]:
    return [
        AccessEntry.model_validate_json(line)
        for path in (directory / "logs").glob("access*")
        for line in path.read_text().splitlines()
    ]
