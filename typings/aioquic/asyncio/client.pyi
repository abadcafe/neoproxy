from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.tls import SessionTicket

type QuicProtocolFactory = Callable[[QuicConnection, QuicStreamHandler | None], QuicConnectionProtocol]

def connect(
    host: str,
    port: int,
    *,
    configuration: QuicConfiguration | None = None,
    create_protocol: type[QuicConnectionProtocol] | QuicProtocolFactory | None = QuicConnectionProtocol,
    session_ticket_handler: Callable[[SessionTicket], None] | None = None,
    stream_handler: QuicStreamHandler | None = None,
    token_handler: Callable[[bytes], None] | None = None,
    wait_connected: bool = True,
    local_port: int = 0,
) -> AbstractAsyncContextManager[QuicConnectionProtocol]: ...
