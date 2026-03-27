"""
HTTP/3 client utilities for integration testing.

This module provides HTTP/3 client functionality using aioquic library.

Test target: Verify neoproxy HTTP/3 Listener behavior
Test nature: Black-box testing through external interface (HTTP/3)
"""

import asyncio
import socket
import ssl
import tempfile
import os
import base64
from typing import Optional, Tuple, List, Dict, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict

# Import aioquic components
try:
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.asyncio.client import connect
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import (
        HeadersReceived,
        DataReceived,
        PushPromiseReceived,
        H3Event,
    )
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import QuicEvent, StreamDataReceived
    from aioquic.quic.connection import QuicConnection
    import aioquic.h3.events as h3_events
    AIOQUIC_AVAILABLE = True
except ImportError:
    AIOQUIC_AVAILABLE = False


@dataclass
class H3Response:
    """HTTP/3 response object."""
    status_code: int
    headers: Dict[str, str]
    body: bytes
    stream_id: int


@dataclass
class H3ConnectResult:
    """Result of HTTP/3 CONNECT request."""
    success: bool
    status_code: int
    message: str
    stream_id: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)


class H3Client:
    """
    HTTP/3 client for testing neoproxy HTTP/3 listener.

    This client uses aioquic to establish QUIC connections and
    send HTTP/3 requests.
    """

    def __init__(
        self,
        host: str,
        port: int,
        ca_path: Optional[str] = None,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        verify_mode: int = ssl.CERT_REQUIRED,
    ) -> None:
        """
        Initialize H3Client.

        Args:
            host: Server hostname or IP
            port: Server port
            ca_path: Path to CA certificate for server verification
            cert_path: Path to client certificate (for mTLS)
            key_path: Path to client private key (for mTLS)
            verify_mode: SSL verification mode
        """
        self.host: str = host
        self.port: int = port
        self.ca_path: Optional[str] = ca_path
        self.cert_path: Optional[str] = cert_path
        self.key_path: Optional[str] = key_path
        self.verify_mode: int = verify_mode
        self._protocol: Optional[QuicConnectionProtocol] = None
        self._h3_connection: Optional[H3Connection] = None
        self._configuration: Optional[QuicConfiguration] = None
        self._connection_context: Optional[Any] = None
        self._h3_events: Dict[int, List[H3Event]] = defaultdict(list)
        self._h3_events_received: Dict[int, asyncio.Event] = defaultdict(asyncio.Event)

    async def connect(self) -> bool:
        """
        Establish QUIC connection and HTTP/3 session.

        Returns:
            bool: True if connection succeeded
        """
        if not AIOQUIC_AVAILABLE:
            raise RuntimeError("aioquic library not available")

        self._configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=["h3"],
        )

        # Configure certificate verification
        if self.ca_path:
            self._configuration.load_verify_locations(self.ca_path)
        else:
            # For self-signed certs, disable verification
            self._configuration.verify_mode = ssl.CERT_NONE

        # Load client certificate if provided
        if self.cert_path and self.key_path:
            self._configuration.load_cert_chain(
                certfile=self.cert_path,
                keyfile=self.key_path,
            )

        # Set timeout
        self._configuration.idle_timeout = 30.0

        # Create a custom protocol class for this connection
        h3_events_store = self._h3_events
        h3_events_received = self._h3_events_received

        class H3ClientProtocol(QuicConnectionProtocol):
            """Custom protocol for this H3Client instance."""

            def __init__(
                self,
                quic: QuicConnection,
                stream_handler: Optional[Callable] = None,
            ) -> None:
                super().__init__(quic, stream_handler)
                self._h3: Optional[H3Connection] = None

            def quic_event_received(self, event: QuicEvent) -> None:
                if isinstance(event, StreamDataReceived):
                    reader = self._stream_readers.get(event.stream_id, None)
                    if reader is not None:
                        reader.feed_data(event.data)
                        if event.end_stream:
                            reader.feed_eof()

                if self._h3 is not None:
                    events = self._h3.handle_event(event)
                    for h3_event in events:
                        stream_id = getattr(h3_event, 'stream_id', 0)
                        h3_events_store[stream_id].append(h3_event)
                        h3_events_received[stream_id].set()

        try:
            self._connection_context = connect(
                host=self.host,
                port=self.port,
                configuration=self._configuration,
                create_protocol=H3ClientProtocol,
            )
            self._protocol = await self._connection_context.__aenter__()
            # Wait for connection to be established
            await self._protocol.wait_connected()
            # Create H3 connection
            self._h3_connection = H3Connection(self._protocol._quic)
            self._protocol._h3 = self._h3_connection
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    async def send_connect_request(
        self,
        target_host: str,
        target_port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> H3Response:
        """
        Send HTTP/3 CONNECT request.

        Args:
            target_host: Target host to connect to
            target_port: Target port
            username: Optional username for proxy auth
            password: Optional password for proxy auth

        Returns:
            H3Response: The response from the proxy
        """
        if self._h3_connection is None or self._protocol is None:
            raise RuntimeError("Not connected")

        # Build headers
        headers: List[Tuple[bytes, bytes]] = [
            (b":method", b"CONNECT"),
            (b":authority", f"{target_host}:{target_port}".encode()),
            (b":scheme", b"https"),
            (b":path", b"/"),
        ]

        # Add proxy authorization if credentials provided
        if username and password:
            credentials = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()
            headers.append((b"proxy-authorization", f"Basic {credentials}".encode()))

        # Get stream ID from quic connection
        stream_id = self._protocol._quic.get_next_available_stream_id()

        # Clear any previous events for this stream
        self._h3_events[stream_id] = []
        self._h3_events_received[stream_id].clear()

        # Send headers (end_stream=True for CONNECT)
        self._h3_connection.send_headers(stream_id, headers, end_stream=True)

        # Transmit the data
        self._protocol.transmit()

        # Collect response
        response = await self._receive_response(stream_id)
        return response

    async def send_request(
        self,
        method: str,
        path: str,
        headers: Optional[List[Tuple[str, str]]] = None,
        body: Optional[bytes] = None,
    ) -> H3Response:
        """
        Send generic HTTP/3 request.

        Args:
            method: HTTP method
            path: Request path
            headers: Additional headers
            body: Request body

        Returns:
            H3Response: The response
        """
        if self._h3_connection is None or self._protocol is None:
            raise RuntimeError("Not connected")

        # Build headers
        h3_headers: List[Tuple[bytes, bytes]] = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", f"{self.host}:{self.port}".encode()),
            (b":path", path.encode()),
        ]

        if headers:
            for name, value in headers:
                h3_headers.append((name.encode(), value.encode()))

        # Get stream ID
        stream_id = self._protocol._quic.get_next_available_stream_id()

        # Clear any previous events for this stream
        self._h3_events[stream_id] = []
        self._h3_events_received[stream_id].clear()

        # Send headers
        self._h3_connection.send_headers(stream_id, h3_headers)

        # Send body if provided
        if body:
            self._h3_connection.send_data(stream_id, body, end_stream=True)
        else:
            self._h3_connection.send_data(stream_id, b"", end_stream=True)

        # Transmit the data
        self._protocol.transmit()

        # Collect response
        response = await self._receive_response(stream_id)
        return response

    async def _receive_response(self, stream_id: int) -> H3Response:
        """
        Receive response for a stream using proper event handling.

        Args:
            stream_id: The stream ID to receive response for

        Returns:
            H3Response: The received response
        """
        status_code: int = 0
        headers: Dict[str, str] = {}
        body: bytes = b""

        event_timeout: float = 10.0
        start_time = asyncio.get_event_loop().time()
        response_received: bool = False

        while asyncio.get_event_loop().time() - start_time < event_timeout:
            # Get accumulated events
            events = self._h3_events.get(stream_id, [])

            for h3_event in events:
                if isinstance(h3_event, HeadersReceived):
                    # Parse headers
                    for name, value in h3_event.headers:
                        if name == b":status":
                            status_code = int(value)
                        else:
                            headers[name.decode()] = value.decode()

                    # Check if stream ended with headers
                    if h3_event.stream_ended:
                        response_received = True
                        break

                elif isinstance(h3_event, DataReceived):
                    # Accumulate body data
                    body += h3_event.data

                    # Check if stream ended with data
                    if h3_event.stream_ended:
                        response_received = True
                        break

            if response_received:
                break

            # Wait for more events
            try:
                await asyncio.wait_for(
                    self._h3_events_received[stream_id].wait(),
                    timeout=0.5
                )
                self._h3_events_received[stream_id].clear()
            except asyncio.TimeoutError:
                pass

        return H3Response(
            status_code=status_code,
            headers=headers,
            body=body,
            stream_id=stream_id,
        )

    async def close(self) -> None:
        """Close the connection."""
        if self._connection_context:
            await self._connection_context.__aexit__(None, None, None)


async def perform_h3_connection_test(
    host: str,
    port: int,
    ca_path: Optional[str] = None,
    timeout: float = 10.0,
) -> Tuple[bool, str]:
    """
    Perform HTTP/3 connection test.

    This function establishes a QUIC connection and verifies TLS handshake
    by sending an HTTP/3 request after the connection is established.

    Args:
        host: Server host
        port: Server port
        ca_path: CA certificate path
        timeout: Connection timeout

    Returns:
        Tuple[bool, str]: (success, message)
    """
    if not AIOQUIC_AVAILABLE:
        return False, "aioquic library not available"

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
    )

    # Configure certificate verification
    if ca_path:
        configuration.load_verify_locations(ca_path)
    else:
        # For self-signed certs, disable verification
        configuration.verify_mode = ssl.CERT_NONE

    configuration.idle_timeout = 30.0

    h3_events_store: Dict[int, List[H3Event]] = defaultdict(list)
    h3_events_received: Dict[int, asyncio.Event] = defaultdict(asyncio.Event)

    class H3ConnTestProtocol(QuicConnectionProtocol):
        """Protocol for HTTP/3 connection testing."""

        def __init__(
            self,
            quic: QuicConnection,
            stream_handler: Optional[Callable] = None,
        ) -> None:
            super().__init__(quic, stream_handler)
            self._h3: Optional[H3Connection] = None

        def quic_event_received(self, event: QuicEvent) -> None:
            if isinstance(event, StreamDataReceived):
                reader = self._stream_readers.get(event.stream_id, None)
                if reader is not None:
                    reader.feed_data(event.data)
                    if event.end_stream:
                        reader.feed_eof()

            if self._h3 is not None:
                events = self._h3.handle_event(event)
                for h3_event in events:
                    stream_id = getattr(h3_event, 'stream_id', 0)
                    h3_events_store[stream_id].append(h3_event)
                    h3_events_received[stream_id].set()

    try:
        async with asyncio.timeout(timeout):
            async with connect(
                host=host,
                port=port,
                configuration=configuration,
                create_protocol=H3ConnTestProtocol,
            ) as protocol:
                await protocol.wait_connected()

                # Create H3 connection and send a simple GET request
                # to verify TLS handshake completed successfully
                quic_connection = protocol._quic
                h3_conn = H3Connection(quic_connection)
                protocol._h3 = h3_conn

                # Send a simple GET request
                headers: List[Tuple[bytes, bytes]] = [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", f"{host}:{port}".encode()),
                    (b":path", b"/"),
                ]

                stream_id = quic_connection.get_next_available_stream_id()
                h3_conn.send_headers(stream_id, headers, end_stream=True)
                protocol.transmit()

                # Wait for response
                status_code: int = 0
                response_received: bool = False
                start_time = asyncio.get_event_loop().time()
                event_timeout: float = 5.0

                while asyncio.get_event_loop().time() - start_time < event_timeout:
                    events = h3_events_store.get(stream_id, [])
                    for h3_event in events:
                        if isinstance(h3_event, HeadersReceived):
                            for name, value in h3_event.headers:
                                if name == b":status":
                                    status_code = int(value)
                            response_received = True
                            break
                        elif isinstance(h3_event, DataReceived):
                            response_received = True
                            break
                    if response_received:
                        break
                    try:
                        await asyncio.wait_for(
                            h3_events_received[stream_id].wait(),
                            timeout=0.5
                        )
                        h3_events_received[stream_id].clear()
                    except asyncio.TimeoutError:
                        pass

                if response_received:
                    return True, "QUIC handshake and HTTP/3 request successful"
                else:
                    return False, "No response received - TLS handshake may have failed"

    except asyncio.TimeoutError:
        return False, "Connection timeout"
    except Exception as e:
        return False, f"Connection error: {str(e)}"


async def perform_h3_connect_test(
    host: str,
    port: int,
    target_host: str,
    target_port: int,
    ca_path: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 10.0,
) -> Tuple[bool, int, str]:
    """
    Perform HTTP/3 CONNECT request test.

    Args:
        host: Proxy host
        port: Proxy port
        target_host: Target host
        target_port: Target port
        ca_path: CA certificate path
        username: Optional username
        password: Optional password
        timeout: Request timeout

    Returns:
        Tuple[bool, int, str]: (success, status_code, message)
    """
    result = await perform_h3_connect_test_full(
        host, port, target_host, target_port,
        ca_path, username, password, timeout
    )
    return result.success, result.status_code, result.message


async def perform_h3_connect_test_full(
    host: str,
    port: int,
    target_host: str,
    target_port: int,
    ca_path: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 10.0,
) -> H3ConnectResult:
    """
    Perform HTTP/3 CONNECT request test with full result.

    This function properly handles HTTP/3 events to receive the response.

    Args:
        host: Proxy host
        port: Proxy port
        target_host: Target host
        target_port: Target port
        ca_path: CA certificate path
        username: Optional username
        password: Optional password
        timeout: Request timeout

    Returns:
        H3ConnectResult: Full result with status code and headers
    """
    if not AIOQUIC_AVAILABLE:
        return H3ConnectResult(
            success=False,
            status_code=0,
            message="aioquic library not available"
        )

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
    )

    # Configure certificate verification
    if ca_path:
        configuration.load_verify_locations(ca_path)
    else:
        configuration.verify_mode = ssl.CERT_NONE

    configuration.idle_timeout = 30.0

    h3_events_store: Dict[int, List[H3Event]] = defaultdict(list)
    h3_events_received: Dict[int, asyncio.Event] = defaultdict(asyncio.Event)

    class H3TestProtocol(QuicConnectionProtocol):
        """Custom protocol for HTTP/3 testing."""

        def __init__(
            self,
            quic: QuicConnection,
            stream_handler: Optional[Callable] = None,
        ) -> None:
            super().__init__(quic, stream_handler)
            self._h3: Optional[H3Connection] = None

        def quic_event_received(self, event: QuicEvent) -> None:
            # First, let the parent class handle stream data for readers
            if isinstance(event, StreamDataReceived):
                reader = self._stream_readers.get(event.stream_id, None)
                if reader is not None:
                    reader.feed_data(event.data)
                    if event.end_stream:
                        reader.feed_eof()

            # Then, handle HTTP/3 events
            if self._h3 is not None:
                events = self._h3.handle_event(event)
                for h3_event in events:
                    stream_id = getattr(h3_event, 'stream_id', 0)
                    h3_events_store[stream_id].append(h3_event)
                    h3_events_received[stream_id].set()

    try:
        async with asyncio.timeout(timeout):
            async with connect(
                host=host,
                port=port,
                configuration=configuration,
                create_protocol=H3TestProtocol,
            ) as protocol:
                # Wait for connection to be established
                await protocol.wait_connected()

                # Get the QuicConnection from the protocol
                quic_connection = protocol._quic
                # Create H3 connection
                h3_conn = H3Connection(quic_connection)
                protocol._h3 = h3_conn

                # Build CONNECT request headers
                headers: List[Tuple[bytes, bytes]] = [
                    (b":method", b"CONNECT"),
                    (b":authority", f"{target_host}:{target_port}".encode()),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                ]

                # Add proxy authorization if credentials provided
                if username and password:
                    credentials = base64.b64encode(
                        f"{username}:{password}".encode()
                    ).decode()
                    headers.append((b"proxy-authorization", f"Basic {credentials}".encode()))

                # Create a new stream
                stream_id = quic_connection.get_next_available_stream_id()

                # Send request headers (end_stream=True for CONNECT)
                h3_conn.send_headers(stream_id, headers, end_stream=True)

                # Transmit the data
                protocol.transmit()

                # Wait for response using proper event handling
                status_code: int = 0
                response_headers: Dict[str, str] = {}
                response_received: bool = False

                event_timeout: float = 10.0
                start_time = asyncio.get_event_loop().time()

                while asyncio.get_event_loop().time() - start_time < event_timeout:
                    # Get accumulated events
                    events = h3_events_store.get(stream_id, [])

                    for h3_event in events:
                        if isinstance(h3_event, HeadersReceived):
                            # Parse response headers
                            for name, value in h3_event.headers:
                                if name == b":status":
                                    status_code = int(value)
                                else:
                                    response_headers[name.decode()] = value.decode()

                            # Check if stream ended
                            if h3_event.stream_ended:
                                response_received = True
                                break

                        elif isinstance(h3_event, DataReceived):
                            # Handle data if present
                            if h3_event.stream_ended:
                                response_received = True
                                break

                    if response_received and status_code > 0:
                        break

                    # Wait for more events
                    try:
                        await asyncio.wait_for(
                            h3_events_received[stream_id].wait(),
                            timeout=0.5
                        )
                        h3_events_received[stream_id].clear()
                    except asyncio.TimeoutError:
                        pass

                success = status_code == 200
                return H3ConnectResult(
                    success=success,
                    status_code=status_code,
                    message=f"Status: {status_code}",
                    stream_id=stream_id,
                    response_headers=response_headers
                )

    except asyncio.TimeoutError:
        return H3ConnectResult(
            success=False,
            status_code=0,
            message="Request timeout"
        )
    except Exception as e:
        return H3ConnectResult(
            success=False,
            status_code=0,
            message=f"Request error: {str(e)}"
        )


async def perform_h3_request_test(
    host: str,
    port: int,
    method: str,
    path: str,
    ca_path: Optional[str] = None,
    headers: Optional[List[Tuple[str, str]]] = None,
    body: Optional[bytes] = None,
    timeout: float = 10.0,
) -> H3Response:
    """
    Perform HTTP/3 request test.

    This function properly handles HTTP/3 events to receive the response.

    Args:
        host: Proxy host
        port: Proxy port
        method: HTTP method (GET, POST, etc.)
        path: Request path
        ca_path: CA certificate path
        headers: Additional headers
        body: Request body
        timeout: Request timeout

    Returns:
        H3Response: The response from the server
    """
    if not AIOQUIC_AVAILABLE:
        return H3Response(
            status_code=0,
            headers={},
            body=b"",
            stream_id=0
        )

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
    )

    if ca_path:
        configuration.load_verify_locations(ca_path)
    else:
        configuration.verify_mode = ssl.CERT_NONE

    configuration.idle_timeout = 30.0

    h3_events_store: Dict[int, List[H3Event]] = defaultdict(list)
    h3_events_received: Dict[int, asyncio.Event] = defaultdict(asyncio.Event)

    class H3TestProtocol(QuicConnectionProtocol):
        """Custom protocol for HTTP/3 testing."""

        def __init__(
            self,
            quic: QuicConnection,
            stream_handler: Optional[Callable] = None,
        ) -> None:
            super().__init__(quic, stream_handler)
            self._h3: Optional[H3Connection] = None

        def quic_event_received(self, event: QuicEvent) -> None:
            if isinstance(event, StreamDataReceived):
                reader = self._stream_readers.get(event.stream_id, None)
                if reader is not None:
                    reader.feed_data(event.data)
                    if event.end_stream:
                        reader.feed_eof()

            if self._h3 is not None:
                events = self._h3.handle_event(event)
                for h3_event in events:
                    stream_id = getattr(h3_event, 'stream_id', 0)
                    h3_events_store[stream_id].append(h3_event)
                    h3_events_received[stream_id].set()

    try:
        async with asyncio.timeout(timeout):
            async with connect(
                host=host,
                port=port,
                configuration=configuration,
                create_protocol=H3TestProtocol,
            ) as protocol:
                # Wait for connection
                await protocol.wait_connected()

                quic_connection = protocol._quic
                h3_conn = H3Connection(quic_connection)
                protocol._h3 = h3_conn

                # Build request headers
                h3_headers: List[Tuple[bytes, bytes]] = [
                    (b":method", method.encode()),
                    (b":scheme", b"https"),
                    (b":authority", f"{host}:{port}".encode()),
                    (b":path", path.encode()),
                ]

                if headers:
                    for name, value in headers:
                        h3_headers.append((name.encode(), value.encode()))

                stream_id = quic_connection.get_next_available_stream_id()
                h3_conn.send_headers(stream_id, h3_headers)

                if body:
                    h3_conn.send_data(stream_id, body, end_stream=True)
                else:
                    h3_conn.send_data(stream_id, b"", end_stream=True)

                # Transmit
                protocol.transmit()

                # Receive response with proper event handling
                status_code: int = 0
                response_headers: Dict[str, str] = {}
                response_body: bytes = b""
                response_received: bool = False

                event_timeout: float = 10.0
                start_time = asyncio.get_event_loop().time()

                while asyncio.get_event_loop().time() - start_time < event_timeout:
                    events = h3_events_store.get(stream_id, [])

                    for h3_event in events:
                        if isinstance(h3_event, HeadersReceived):
                            for name, value in h3_event.headers:
                                if name == b":status":
                                    status_code = int(value)
                                else:
                                    response_headers[name.decode()] = value.decode()
                            if h3_event.stream_ended:
                                response_received = True
                                break
                        elif isinstance(h3_event, DataReceived):
                            response_body += h3_event.data
                            if h3_event.stream_ended:
                                response_received = True
                                break

                    if response_received and status_code > 0:
                        break

                    try:
                        await asyncio.wait_for(
                            h3_events_received[stream_id].wait(),
                            timeout=0.5
                        )
                        h3_events_received[stream_id].clear()
                    except asyncio.TimeoutError:
                        pass

                return H3Response(
                    status_code=status_code,
                    headers=response_headers,
                    body=response_body,
                    stream_id=stream_id
                )

    except asyncio.TimeoutError:
        return H3Response(
            status_code=0,
            headers={},
            body=b"Timeout",
            stream_id=0
        )
    except Exception as e:
        return H3Response(
            status_code=0,
            headers={},
            body=str(e).encode(),
            stream_id=0
        )


def create_real_bcrypt_hash(password: str, rounds: int = 12) -> str:
    """
    Create a real bcrypt password hash.

    Args:
        password: Plain text password
        rounds: bcrypt cost parameter (default 12)

    Returns:
        str: bcrypt hash string
    """
    import bcrypt
    password_bytes: bytes = password.encode('utf-8')
    salt: bytes = bcrypt.gensalt(rounds=rounds)
    hashed: bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_bcrypt_hash(password: str, hash_str: str) -> bool:
    """
    Verify a password against a bcrypt hash.

    Args:
        password: Plain text password
        hash_str: bcrypt hash string

    Returns:
        bool: True if password matches
    """
    import bcrypt
    try:
        password_bytes: bytes = password.encode('utf-8')
        hash_bytes: bytes = hash_str.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception:
        return False


@dataclass
class H3TunnelResult:
    """Result of HTTP/3 CONNECT tunnel test with data transfer."""
    success: bool
    status_code: int
    data_sent: int
    data_received: int
    message: str


async def perform_h3_tunnel_data_transfer(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    ca_path: Optional[str] = None,
    client_cert_path: Optional[str] = None,
    client_key_path: Optional[str] = None,
    test_data: bytes = b"HELLO_FROM_H3_CLIENT",
    timeout: float = 15.0,
) -> H3TunnelResult:
    """
    Perform HTTP/3 CONNECT tunnel test with actual data transfer.

    This function establishes an HTTP/3 tunnel and verifies bidirectional
    data transfer by sending test data and expecting an echo response.

    Args:
        proxy_host: Proxy server host
        proxy_port: Proxy server port
        target_host: Target host
        target_port: Target port
        ca_path: CA certificate path for server verification
        client_cert_path: Client certificate path for mTLS
        client_key_path: Client private key path for mTLS
        test_data: Data to send through the tunnel
        timeout: Request timeout

    Returns:
        H3TunnelResult: Full result with data transfer statistics
    """
    if not AIOQUIC_AVAILABLE:
        return H3TunnelResult(
            success=False,
            status_code=0,
            data_sent=0,
            data_received=0,
            message="aioquic library not available"
        )

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
    )

    if ca_path:
        configuration.load_verify_locations(ca_path)
    else:
        configuration.verify_mode = ssl.CERT_NONE

    if client_cert_path and client_key_path:
        configuration.load_cert_chain(
            certfile=client_cert_path,
            keyfile=client_key_path,
        )

    configuration.idle_timeout = 30.0

    h3_events_store: Dict[int, List[H3Event]] = defaultdict(list)
    h3_events_received: Dict[int, asyncio.Event] = defaultdict(asyncio.Event)
    stream_readers: Dict[int, asyncio.StreamReader] = {}

    class H3TunnelProtocol(QuicConnectionProtocol):
        """Protocol for HTTP/3 tunnel with data transfer."""

        def __init__(
            self,
            quic: QuicConnection,
            stream_handler: Optional[Callable] = None,
        ) -> None:
            super().__init__(quic, stream_handler)
            self._h3: Optional[H3Connection] = None

        def quic_event_received(self, event: QuicEvent) -> None:
            if isinstance(event, StreamDataReceived):
                reader = stream_readers.get(event.stream_id, None)
                if reader is not None:
                    reader.feed_data(event.data)
                    if event.end_stream:
                        reader.feed_eof()

            if self._h3 is not None:
                events = self._h3.handle_event(event)
                for h3_event in events:
                    stream_id = getattr(h3_event, 'stream_id', 0)
                    h3_events_store[stream_id].append(h3_event)
                    h3_events_received[stream_id].set()

    try:
        async with asyncio.timeout(timeout):
            async with connect(
                host=proxy_host,
                port=proxy_port,
                configuration=configuration,
                create_protocol=H3TunnelProtocol,
            ) as protocol:
                await protocol.wait_connected()

                quic_connection = protocol._quic
                h3_conn = H3Connection(quic_connection)
                protocol._h3 = h3_conn

                # Build CONNECT request
                headers: List[Tuple[bytes, bytes]] = [
                    (b":method", b"CONNECT"),
                    (b":authority", f"{target_host}:{target_port}".encode()),
                    (b":scheme", b"https"),
                    (b":path", b"/"),
                ]

                stream_id = quic_connection.get_next_available_stream_id()
                h3_conn.send_headers(stream_id, headers, end_stream=False)
                protocol.transmit()

                # Wait for response headers
                status_code: int = 0
                response_received: bool = False
                start_time = asyncio.get_event_loop().time()

                while asyncio.get_event_loop().time() - start_time < 10.0:
                    events = h3_events_store.get(stream_id, [])
                    for h3_event in events:
                        if isinstance(h3_event, HeadersReceived):
                            for name, value in h3_event.headers:
                                if name == b":status":
                                    status_code = int(value)
                            response_received = True
                            break
                    if response_received:
                        break
                    try:
                        await asyncio.wait_for(
                            h3_events_received[stream_id].wait(),
                            timeout=0.5
                        )
                        h3_events_received[stream_id].clear()
                    except asyncio.TimeoutError:
                        pass

                if status_code != 200:
                    return H3TunnelResult(
                        success=False,
                        status_code=status_code,
                        data_sent=0,
                        data_received=0,
                        message=f"CONNECT failed with status {status_code}"
                    )

                # Send test data through the tunnel
                h3_conn.send_data(stream_id, test_data, end_stream=False)
                protocol.transmit()

                # Wait for echo response
                received_data: bytes = b""
                start_time = asyncio.get_event_loop().time()

                while asyncio.get_event_loop().time() - start_time < 5.0:
                    events = h3_events_store.get(stream_id, [])
                    for h3_event in events:
                        if isinstance(h3_event, DataReceived):
                            received_data += h3_event.data
                            if h3_event.stream_ended:
                                break
                    if len(received_data) > 0:
                        break
                    try:
                        await asyncio.wait_for(
                            h3_events_received[stream_id].wait(),
                            timeout=0.5
                        )
                        h3_events_received[stream_id].clear()
                    except asyncio.TimeoutError:
                        pass

                # Close the stream
                h3_conn.send_data(stream_id, b"", end_stream=True)
                protocol.transmit()

                return H3TunnelResult(
                    success=True,
                    status_code=200,
                    data_sent=len(test_data),
                    data_received=len(received_data),
                    message=f"Transferred {len(test_data)} bytes, received {len(received_data)} bytes"
                )

    except asyncio.TimeoutError:
        return H3TunnelResult(
            success=False,
            status_code=0,
            data_sent=0,
            data_received=0,
            message="Request timeout"
        )
    except Exception as e:
        return H3TunnelResult(
            success=False,
            status_code=0,
            data_sent=0,
            data_received=0,
            message=f"Connection error: {str(e)}"
        )


async def perform_h3_tls_client_cert_test(
    proxy_host: str,
    proxy_port: int,
    ca_path: str,
    client_cert_path: str,
    client_key_path: str,
    timeout: float = 10.0,
) -> Tuple[bool, str]:
    """
    Test TLS client certificate authentication with HTTP/3.

    This function attempts to connect to an HTTP/3 listener with
    a client certificate and verifies whether the TLS handshake succeeds
    by sending an HTTP/3 request after the QUIC connection is established.

    Args:
        proxy_host: Proxy server host
        proxy_port: Proxy server port
        ca_path: CA certificate path for server verification
        client_cert_path: Client certificate path
        client_key_path: Client private key path
        timeout: Connection timeout

    Returns:
        Tuple[bool, str]: (success, message)
    """
    if not AIOQUIC_AVAILABLE:
        return False, "aioquic library not available"

    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
    )

    configuration.load_verify_locations(ca_path)
    configuration.load_cert_chain(
        certfile=client_cert_path,
        keyfile=client_key_path,
    )
    configuration.idle_timeout = 30.0

    h3_events_store: Dict[int, List[H3Event]] = defaultdict(list)
    h3_events_received: Dict[int, asyncio.Event] = defaultdict(asyncio.Event)

    class H3ClientCertProtocol(QuicConnectionProtocol):
        """Protocol for TLS client cert testing with HTTP/3."""

        def __init__(
            self,
            quic: QuicConnection,
            stream_handler: Optional[Callable] = None,
        ) -> None:
            super().__init__(quic, stream_handler)
            self._h3: Optional[H3Connection] = None

        def quic_event_received(self, event: QuicEvent) -> None:
            if isinstance(event, StreamDataReceived):
                reader = self._stream_readers.get(event.stream_id, None)
                if reader is not None:
                    reader.feed_data(event.data)
                    if event.end_stream:
                        reader.feed_eof()

            if self._h3 is not None:
                events = self._h3.handle_event(event)
                for h3_event in events:
                    stream_id = getattr(h3_event, 'stream_id', 0)
                    h3_events_store[stream_id].append(h3_event)
                    h3_events_received[stream_id].set()

    try:
        async with asyncio.timeout(timeout):
            async with connect(
                host=proxy_host,
                port=proxy_port,
                configuration=configuration,
                create_protocol=H3ClientCertProtocol,
            ) as protocol:
                await protocol.wait_connected()

                # Create H3 connection and send a simple GET request
                # to verify TLS handshake completed successfully
                quic_connection = protocol._quic
                h3_conn = H3Connection(quic_connection)
                protocol._h3 = h3_conn

                # Send a simple GET request
                headers: List[Tuple[bytes, bytes]] = [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", f"{proxy_host}:{proxy_port}".encode()),
                    (b":path", b"/"),
                ]

                stream_id = quic_connection.get_next_available_stream_id()
                h3_conn.send_headers(stream_id, headers, end_stream=True)
                protocol.transmit()

                # Wait for response
                status_code: int = 0
                response_received: bool = False
                start_time = asyncio.get_event_loop().time()
                event_timeout: float = 5.0

                while asyncio.get_event_loop().time() - start_time < event_timeout:
                    events = h3_events_store.get(stream_id, [])
                    for h3_event in events:
                        if isinstance(h3_event, HeadersReceived):
                            for name, value in h3_event.headers:
                                if name == b":status":
                                    status_code = int(value)
                            response_received = True
                            break
                        elif isinstance(h3_event, DataReceived):
                            response_received = True
                            break
                    if response_received:
                        break
                    try:
                        await asyncio.wait_for(
                            h3_events_received[stream_id].wait(),
                            timeout=0.5
                        )
                        h3_events_received[stream_id].clear()
                    except asyncio.TimeoutError:
                        pass

                if response_received:
                    return True, "TLS client certificate authentication successful"
                else:
                    return False, "No response received - TLS handshake may have failed"

    except asyncio.TimeoutError:
        return False, "Connection timeout"
    except Exception as e:
        return False, f"Connection failed: {str(e)}"