"""Public certificate issuance contracts, including authority identity reuse."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tests.fixtures.certificates import (
    generate_ca,
    generate_client_cert,
    generate_server_cert,
)


def test_generate_certificates_keeps_generated_authority_in_memory(
    tmp_path: Path,
) -> None:
    ca, key = generate_ca(str(tmp_path))
    with patch.object(
        serialization, "load_pem_private_key", wraps=serialization.load_pem_private_key
    ) as load:
        server, _ = generate_server_cert(str(tmp_path), ca, key, ["localhost"])
        client, _ = generate_client_cert(str(tmp_path), ca, key)
        assert load.call_count == 0
    authority = x509.load_pem_x509_certificate(Path(ca).read_bytes())
    for path in (server, client):
        certificate = x509.load_pem_x509_certificate(Path(path).read_bytes())
        certificate.verify_directly_issued_by(authority)


def test_generate_certificates_validates_external_authority_only_once(
    tmp_path: Path,
) -> None:
    program = """import sys
from tests.fixtures.certificates import generate_ca

_ = generate_ca(sys.argv[1])
"""
    _ = subprocess.run([sys.executable, "-c", program, str(tmp_path)], check=True)
    ca, key = str(tmp_path / "ca.crt"), str(tmp_path / "ca.key")
    with patch.object(
        serialization, "load_pem_private_key", wraps=serialization.load_pem_private_key
    ) as load:
        server, _ = generate_server_cert(str(tmp_path), ca, key, ["localhost"])
        client, _ = generate_client_cert(str(tmp_path), ca, key)
        assert load.call_count == 1
    authority = x509.load_pem_x509_certificate(Path(ca).read_bytes())
    for path in (server, client):
        certificate = x509.load_pem_x509_certificate(Path(path).read_bytes())
        certificate.verify_directly_issued_by(authority)


def test_generate_certificates_observes_replaced_authority_files(
    tmp_path: Path,
) -> None:
    ca, key = generate_ca(str(tmp_path), cn="first")
    first, _ = generate_server_cert(str(tmp_path), ca, key, ["localhost"], "first")
    ca, key = generate_ca(str(tmp_path), cn="second")
    second, _ = generate_server_cert(str(tmp_path), ca, key, ["localhost"], "second")
    first_certificate = x509.load_pem_x509_certificate(Path(first).read_bytes())
    second_certificate = x509.load_pem_x509_certificate(Path(second).read_bytes())
    authority = x509.load_pem_x509_certificate(Path(ca).read_bytes())
    assert first_certificate.issuer != second_certificate.issuer
    second_certificate.verify_directly_issued_by(authority)
