"""module: certificates; responsibility: issue isolated test certificates.
Public operations: generate_ca, generate_server_cert, generate_client_cert,
generate_test_certificates, CertPair, TestCertBundle.
Data entities: CertPair, TestCertBundle, Authority, AuthorityBytes.
Tests: certificates_tests.py and TLS process contracts.

Retain validated authority objects instead of repeating expensive RSA
validation on every certificate issuance. New authorities remain independent.
"""

import datetime
import ipaddress
import os
import random
import threading
from collections import OrderedDict
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

type CertPair = tuple[str, str]
type TestCertBundle = tuple[str, str, str, str]
type Authority = tuple[x509.Certificate, RSAPrivateKey]
type AuthorityBytes = tuple[bytes, bytes]

_authorities: OrderedDict[AuthorityBytes, Authority] = OrderedDict()
_authority_lock = threading.Lock()


def _retain_authority(identity: AuthorityBytes, authority: Authority) -> None:
    """Update the bounded cache while the caller holds its lock."""
    _authorities[identity] = authority
    _authorities.move_to_end(identity)
    if len(_authorities) > 64:
        _ = _authorities.popitem(last=False)


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, 2048)


def _write_key(path: str, key: RSAPrivateKey) -> None:
    with open(path, "wb") as f:
        _ = f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


def _write_cert(path: str, cert: x509.Certificate) -> None:
    with open(path, "wb") as f:
        _ = f.write(cert.public_bytes(serialization.Encoding.PEM))


def _load_ca(ca_cert_path: str, ca_key_path: str) -> Authority:
    identity = (Path(ca_cert_path).read_bytes(), Path(ca_key_path).read_bytes())
    with _authority_lock:
        if (authority := _authorities.get(identity)) is not None:
            _authorities.move_to_end(identity)
            return authority
        ca_cert = x509.load_pem_x509_certificate(identity[0])
        ca_key = serialization.load_pem_private_key(identity[1], password=None)
        assert isinstance(ca_key, RSAPrivateKey)
        authority = (ca_cert, ca_key)
        _retain_authority(identity, authority)
        return authority


def generate_ca(
    temp_dir: str,
    cn: str = "Test CA",
) -> CertPair:
    """Generate a self-signed CA certificate.

    Returns:
      (ca_cert_path, ca_key_path)
    """
    key = _make_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    ca_cert_path = os.path.join(temp_dir, "ca.crt")
    ca_key_path = os.path.join(temp_dir, "ca.key")
    _write_cert(ca_cert_path, cert)
    _write_key(ca_key_path, key)
    identity = (Path(ca_cert_path).read_bytes(), Path(ca_key_path).read_bytes())
    with _authority_lock:
        _retain_authority(identity, (cert, key))
    return ca_cert_path, ca_key_path


def generate_server_cert(
    temp_dir: str,
    ca_cert_path: str,
    ca_key_path: str,
    san_entries: list[str],
    cert_name: str = "server",
) -> CertPair:
    """Generate a server certificate signed by the given CA.

    Args:
      san_entries: SAN entries as strings. DNS names support wildcards
        like "*.example.com". IP addresses like "127.0.0.1" are
        auto-detected and encoded as IP SANs.

    Returns:
      (server_cert_path, server_key_path)
    """
    ca_cert, ca_key = _load_ca(ca_cert_path, ca_key_path)
    key = _make_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, san_entries[0]),
        ]
    )

    san_names: list[x509.GeneralName] = []
    for entry in san_entries:
        try:
            san_names.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_names.append(x509.DNSName(entry))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(random.randint(1, 2**64))
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_cert_path = os.path.join(temp_dir, f"{cert_name}.crt")
    server_key_path = os.path.join(temp_dir, f"{cert_name}.key")
    _write_cert(server_cert_path, cert)
    _write_key(server_key_path, key)
    return server_cert_path, server_key_path


def generate_client_cert(
    temp_dir: str,
    ca_cert_path: str,
    ca_key_path: str,
    client_name: str = "testclient",
) -> CertPair:
    """Generate a client certificate signed by the given CA.

    Returns:
      (client_cert_path, client_key_path)
    """
    ca_cert, ca_key = _load_ca(ca_cert_path, ca_key_path)
    key = _make_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, client_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(random.randint(1, 2**64))
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    client_cert_path = os.path.join(temp_dir, f"{client_name}.crt")
    client_key_path = os.path.join(temp_dir, f"{client_name}.key")
    _write_cert(client_cert_path, cert)
    _write_key(client_key_path, key)
    return client_cert_path, client_key_path


def generate_test_certificates(
    temp_dir: str,
    *,
    san_entries: list[str] | None = None,
) -> TestCertBundle:
    """Generate CA + server certificate pair for testing.

    Returns:
      (server_cert_path, server_key_path, ca_cert_path, ca_key_path)
    """
    ca_cert_path, ca_key_path = generate_ca(temp_dir)
    server_cert_path, server_key_path = generate_server_cert(
        temp_dir,
        ca_cert_path,
        ca_key_path,
        san_entries=san_entries
        if san_entries is not None
        else ["localhost", "127.0.0.1"],
    )
    return server_cert_path, server_key_path, ca_cert_path, ca_key_path
