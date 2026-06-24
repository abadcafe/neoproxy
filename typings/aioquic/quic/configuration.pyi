import ssl

class QuicConfiguration:
    verify_mode: ssl.VerifyMode
    idle_timeout: float
    server_name: str | None

    def __init__(
        self,
        *,
        is_client: bool = False,
        alpn_protocols: list[str] | None = None,
    ) -> None: ...
    def load_verify_locations(self, cafile: str) -> None: ...
    def load_cert_chain(
        self, certfile: str, keyfile: str | None = None, password: bytes | str | None = None
    ) -> None: ...
