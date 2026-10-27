"""module: matrix_model; responsibility: describe two-hop protocol contracts.
Public operations/data: ChainCase, AuthCase, CertificateFiles and protocol aliases.
Tests: chain matrix local, Baidu and authentication process contracts.
"""

from typing import Literal

from pydantic import BaseModel

type ProxyProtocol = Literal["http", "https", "http3", "socks5"]
type TargetScheme = Literal["http", "https"]
type RequestMode = Literal["forward", "tunnel"]
type RequestMethod = Literal["GET", "HEAD", "POST"]


class ChainCase(BaseModel):
    entry: ProxyProtocol
    relay: ProxyProtocol
    scheme: TargetScheme = "https"
    mode: RequestMode = "tunnel"
    method: RequestMethod = "GET"

    @property
    def label(self) -> str:
        return f"{self.entry}-{self.relay}-{self.mode}-{self.scheme}-{self.method}"


class AuthCase(BaseModel):
    hop: Literal["entry", "relay"]
    policy: Literal["password", "certificate", "both"]
    fault: Literal[
        "none",
        "missing_password",
        "wrong_password",
        "missing_certificate",
        "wrong_certificate",
    ] = "none"

    @property
    def password_required(self) -> bool:
        return self.policy in ("password", "both")

    @property
    def certificate_required(self) -> bool:
        return self.policy in ("certificate", "both")


class CertificateFiles(BaseModel):
    server_cert: str
    server_key: str
    ca: str
    client_cert: str
    client_key: str
    alien_cert: str
    alien_key: str
