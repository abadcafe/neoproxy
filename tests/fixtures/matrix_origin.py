"""module: matrix_origin; responsibility: serve observable local HTTP targets.
Public operations: local_origin. Data entities: Origin.
Tests: test_chain_matrix_local.py.
"""

import ssl
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import override

from pydantic import BaseModel, Field

from .matrix_model import CertificateFiles, TargetScheme
from .matrix_observation import OriginRequest


class ResponseTiming(BaseModel):
    body_delay: float = Field(default=0, ge=0)
    byte_interval: float = Field(default=0, ge=0)


@dataclass
class Origin:
    url: str
    requests: list[OriginRequest]


@contextmanager
def local_origin(
    scheme: TargetScheme,
    certificates: CertificateFiles,
    timing: ResponseTiming | None = None,
) -> Generator[Origin]:
    requests: list[OriginRequest] = []
    schedule = timing or ResponseTiming()

    class Handler(BaseHTTPRequestHandler):
        protocol_version: str = "HTTP/1.1"

        @override
        def log_message(self, format: str, *args: object) -> None:
            pass

        def respond(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append(OriginRequest(self.command, self.path, body))
            payload = body if self.command == "POST" else b"matrix-origin"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                time.sleep(schedule.body_delay)
                try:
                    if schedule.byte_interval:
                        for byte in payload:
                            _ = self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(schedule.byte_interval)
                    else:
                        _ = self.wfile.write(payload)
                except BrokenPipeError, ConnectionResetError, ssl.SSLError:
                    # A tunnel may expire while this controlled origin is idle.
                    pass

        def do_GET(self) -> None:
            self.respond()

        def do_HEAD(self) -> None:
            self.respond()

        def do_POST(self) -> None:
            self.respond()

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        if scheme == "https":
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(certificates.server_cert, certificates.server_key)
            tls.set_alpn_protocols(["http/1.1"])
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        thread.start()
        try:
            yield Origin(f"{scheme}://127.0.0.1:{server.server_port}/matrix", requests)
        finally:
            server.shutdown()
            thread.join()
