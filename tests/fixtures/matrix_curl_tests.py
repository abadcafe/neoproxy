"""Public command contracts: retain verification for public and local targets."""

from pathlib import Path

from .matrix_curl import curl_command
from .matrix_model import CertificateFiles, ChainCase


def test_curl_command_preserves_public_ca_trust(tmp_path: Path) -> None:
    certs = CertificateFiles(
        server_cert="server.pem",
        server_key="server.key",
        ca="test-ca.pem",
        client_cert="client.pem",
        client_key="client.key",
        alien_cert="alien.pem",
        alien_key="alien.key",
    )
    command = curl_command(
        tmp_path,
        ChainCase(entry="http", relay="http"),
        8080,
        "https://cloudflare.com/",
        certs,
        None,
        b"",
    )
    assert "--cacert" not in command
    assert "--proxy-cacert" in command
    assert "--insecure" not in command
    assert "--proxy-insecure" not in command


def test_curl_command_requires_h3_for_forwarding(tmp_path: Path) -> None:
    certs = CertificateFiles(
        server_cert="server.pem",
        server_key="server.key",
        ca="test-ca.pem",
        client_cert="client.pem",
        client_key="client.key",
        alien_cert="alien.pem",
        alien_key="alien.key",
    )
    command = curl_command(
        tmp_path,
        ChainCase(entry="http3", relay="http", mode="forward"),
        8080,
        "https://127.0.0.1/",
        certs,
        None,
        b"",
    )
    assert "--http3-only" in command
    assert "--http1.1" not in command
