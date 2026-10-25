import asyncio
from collections.abc import Callable

from aioquic.asyncio.client import QuicProtocolFactory
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import SessionTicket

class QuicServer(asyncio.DatagramProtocol):
    def close(self) -> None: ...

async def serve(
    host: str,
    port: int,
    *,
    configuration: QuicConfiguration,
    create_protocol: type[QuicConnectionProtocol]
    | QuicProtocolFactory = QuicConnectionProtocol,
    session_ticket_fetcher: Callable[[bytes], SessionTicket | None] | None = None,
    session_ticket_handler: Callable[[SessionTicket], None] | None = None,
    retry: bool = False,
    stream_handler: QuicStreamHandler | None = None,
) -> QuicServer: ...
