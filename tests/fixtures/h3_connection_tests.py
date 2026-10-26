"""Wire contract for H3 authentication probes."""

import asyncio
from pathlib import Path

import pytest

from .h3_capture import RESPONSE_BODY, capture_peer
from .h3_connection import perform_h3_connection_test


@pytest.mark.asyncio
async def test_perform_h3_connection_test_stops_at_authenticated_proxy(
    tmp_path: Path,
) -> None:
    async with capture_peer(tmp_path) as peer:
        success, status, message = await perform_h3_connection_test(
            "127.0.0.1", peer.port, ca_path=peer.ca_path, timeout=2
        )
        request = await asyncio.wait_for(peer.received.get(), timeout=1)

    assert success
    assert status == 201
    assert message == RESPONSE_BODY.decode(errors="replace")
    fields = dict(request.headers)
    assert fields[b":method"] == b"OPTIONS"
    assert fields[b"max-forwards"] == b"0"
