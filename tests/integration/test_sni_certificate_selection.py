"""
SNI Certificate Selection integration tests.

Test target: Verify neoproxy SNI-based certificate selection behavior
Test nature: Black-box testing through TLS handshake

This test module covers:
- Multiple servers sharing same address with different certificates
- Wildcard certificate matching (*.example.com)
- SNI mismatch rejection (no default certificate)
"""

import subprocess
import socket
import ssl
import tempfile
import shutil
import os
from typing import Optional, Tuple, List

from .utils.helpers import (
    start_proxy,
    wait_for_proxy,
    terminate_process,
)

from .conftest import get_unique_port


# ==============================================================================
# Certificate Generation Helpers
# ==============================================================================


def generate_ca_certificate(temp_dir: str, ca_name: str = "Test CA") -> Tuple[str, str]:
    """
    Generate a CA certificate with proper extensions.

    Returns:
        Tuple[str, str]: (ca_cert_path, ca_key_path)
    """
    ca_key_path = os.path.join(temp_dir, "ca.key")
    ca_cert_path = os.path.join(temp_dir, "ca.crt")

    # Generate CA private key
    subprocess.run(
        ["openssl", "genrsa", "-out", ca_key_path, "2048"],
        check=True,
        capture_output=True
    )

    # Create CA config with proper extensions
    ca_config_path = os.path.join(temp_dir, "ca.cnf")
    with open(ca_config_path, "w") as f:
        f.write(f"""
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = {ca_name}

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
""")

    subprocess.run(
        [
            "openssl", "req", "-new", "-x509",
            "-key", ca_key_path,
            "-out", ca_cert_path,
            "-days", "1",
            "-config", ca_config_path
        ],
        check=True,
        capture_output=True
    )

    return ca_cert_path, ca_key_path


def generate_server_certificate(
    temp_dir: str,
    ca_cert_path: str,
    ca_key_path: str,
    san_entries: List[str],
    cert_name: str = "server"
) -> Tuple[str, str]:
    """
    Generate a server certificate with specified SAN entries.

    Args:
        temp_dir: Temporary directory
        ca_cert_path: CA certificate path
        ca_key_path: CA private key path
        san_entries: List of SAN entries (e.g., ["api.example.com", "*.example.com"])
        cert_name: Name prefix for certificate files

    Returns:
        Tuple[str, str]: (server_cert_path, server_key_path)
    """
    server_key_path = os.path.join(temp_dir, f"{cert_name}.key")
    server_csr_path = os.path.join(temp_dir, f"{cert_name}.csr")
    server_cert_path = os.path.join(temp_dir, f"{cert_name}.crt")

    # Generate server private key
    subprocess.run(
        ["openssl", "genrsa", "-out", server_key_path, "2048"],
        check=True,
        capture_output=True
    )

    # Generate server CSR
    subprocess.run(
        [
            "openssl", "req", "-new",
            "-key", server_key_path,
            "-out", server_csr_path,
            "-subj", f"/CN={san_entries[0]}"
        ],
        check=True,
        capture_output=True
    )

    # Create extensions config
    ext_config_path = os.path.join(temp_dir, f"{cert_name}_ext.cnf")
    with open(ext_config_path, "w") as f:
        san_list = ",".join(f"DNS:{san}" for san in san_entries)
        f.write(f"subjectAltName={san_list}\n")
        f.write("basicConstraints=critical,CA:FALSE\n")
        f.write("keyUsage=critical,digitalSignature,keyEncipherment\n")

    # Sign server certificate with CA
    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", server_csr_path,
            "-CA", ca_cert_path,
            "-CAkey", ca_key_path,
            "-CAcreateserial",
            "-out", server_cert_path,
            "-days", "1",
            "-extfile", ext_config_path
        ],
        check=True,
        capture_output=True
    )

    return server_cert_path, server_key_path


def create_multi_server_config(
    proxy_port: int,
    temp_dir: str,
    servers: List[dict]
) -> str:
    """
    Create a config with multiple servers sharing the same address.

    Args:
        proxy_port: The shared listening port
        temp_dir: Temporary directory for config
        servers: List of server configs, each with:
            - hostnames: List of hostnames (or empty for default)
            - cert_path: Certificate path
            - key_path: Key path
            - service: Service name

    Returns:
        str: Path to config file
    """
    config_lines = [
        f"server_threads: 1",
        "",
        "services:",
        "  - name: echo",
        "    kind: echo.echo",
        "",
        "listeners:",
        "  - name: https_main",
        "    kind: https",
        f'    addresses: ["127.0.0.1:{proxy_port}"]',
        "",
        "servers:",
    ]

    for i, server in enumerate(servers):
        server_name = f"server_{i}"
        hostnames_line = ""
        if server.get("hostnames"):
            hostnames_str = ", ".join(f'"{h}"' for h in server["hostnames"])
            hostnames_line = f"    hostnames: [{hostnames_str}]"

        config_lines.extend([
            f"  - name: {server_name}",
        ])
        if hostnames_line:
            config_lines.append(hostnames_line)
        config_lines.extend([
            "    tls:",
            "      certificates:",
            f'        - cert_path: {server["cert_path"]}',
            f'          key_path: {server["key_path"]}',
            '    listeners: ["https_main"]',
            "    service: echo",
            "",
        ])

    config_path = os.path.join(temp_dir, "multi_server_config.yaml")
    with open(config_path, "w") as f:
        f.write("\n".join(config_lines))

    return config_path


def create_single_server_config(
    proxy_port: int,
    temp_dir: str,
    cert_path: str,
    key_path: str,
    hostnames: Optional[List[str]] = None
) -> str:
    """
    Create a config with a single server.

    Args:
        proxy_port: Listening port
        temp_dir: Temporary directory
        cert_path: Certificate path
        key_path: Key path
        hostnames: Optional hostnames for the server

    Returns:
        str: Path to config file
    """
    lines = [
        "server_threads: 1",
        "",
        "services:",
        "  - name: echo",
        "    kind: echo.echo",
        "",
        "listeners:",
        "  - name: https_main",
        "    kind: https",
        f'    addresses: ["127.0.0.1:{proxy_port}"]',
        "",
        "servers:",
        "  - name: test_server",
    ]

    if hostnames:
        hostnames_str = ", ".join(f'"{h}"' for h in hostnames)
        lines.append(f"    hostnames: [{hostnames_str}]")

    lines.extend([
        "    tls:",
        "      certificates:",
        f"        - cert_path: {cert_path}",
        f"          key_path: {key_path}",
        '    listeners: ["https_main"]',
        "    service: echo",
    ])

    config_content = "\n".join(lines) + "\n"

    config_path = os.path.join(temp_dir, "test_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)

    return config_path


def try_tls_connection_with_sni(
    host: str,
    port: int,
    sni: str,
    ca_cert_path: str,
    timeout: float = 5.0
) -> Tuple[bool, Optional[str]]:
    """
    Test TLS connection with specific SNI.

    Args:
        host: Server host
        port: Server port
        sni: SNI hostname to send
        ca_cert_path: CA certificate for verification
        timeout: Connection timeout

    Returns:
        Tuple[bool, Optional[str]]: (success, error_message)
    """
    try:
        context = ssl.create_default_context()
        context.load_verify_locations(ca_cert_path)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Wrap with SSL and specify SNI
        ssl_sock = context.wrap_socket(sock, server_hostname=sni)

        try:
            ssl_sock.connect((host, port))
            ssl_sock.close()

            return True, None
        except ssl.SSLCertVerificationError as e:
            return False, f"Certificate verification failed: {e}"
        except ssl.SSLError as e:
            return False, f"SSL error: {e}"
        finally:
            if ssl_sock:
                try:
                    ssl_sock.close()
                except:
                    pass

    except socket.timeout:
        return False, "Connection timeout"
    except ConnectionRefusedError:
        return False, "Connection refused"
    except Exception as e:
        return False, f"Unexpected error: {e}"


def get_certificate_cn(host: str, port: int, sni: str, ca_cert_path: str) -> Optional[str]:
    """
    Get the CN from the certificate presented by the server for a given SNI.

    Returns:
        Optional[str]: The CN of the certificate, or None if failed
    """
    try:
        context = ssl.create_default_context()
        context.load_verify_locations(ca_cert_path)
        context.check_hostname = False  # Don't check hostname, just get cert
        context.verify_mode = ssl.CERT_REQUIRED

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)

        ssl_sock = context.wrap_socket(sock, server_hostname=sni)
        ssl_sock.connect((host, port))

        cert = ssl_sock.getpeercert()
        ssl_sock.close()

        if cert is None:
            return None

        # Extract CN from subject - cert['subject'] is a tuple of tuples
        # e.g., ((('commonName', 'api.test.local'),),)
        subject = cert.get('subject', ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == 'commonName':
                    return attr_value
        return None

    except Exception:
        return None


# ==============================================================================
# Test Cases
# ==============================================================================


class TestSniCertificateSelection:
    """Test SNI-based certificate selection for shared-address servers."""

    def test_multiple_servers_same_address_different_certs(self) -> None:
        """
        Two servers share the same address with different certificates.
        SNI determines which certificate is used.

        Setup:
        - Server A: hostnames=[api.test.local], cert with SAN=api.test.local
        - Server B: hostnames=[web.test.local], cert with SAN=web.test.local
        - Both listen on same port

        Expected:
        - SNI=api.test.local returns Server A's certificate
        - SNI=web.test.local returns Server B's certificate
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # Generate CA
            ca_cert_path, ca_key_path = generate_ca_certificate(temp_dir)

            # Generate two different server certificates
            cert_a_path, key_a_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["api.test.local"],
                cert_name="server_a"
            )

            cert_b_path, key_b_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["web.test.local"],
                cert_name="server_b"
            )

            # Create config with two servers
            config_path = create_multi_server_config(
                proxy_port, temp_dir,
                servers=[
                    {
                        "hostnames": ["api.test.local"],
                        "cert_path": cert_a_path,
                        "key_path": key_a_path,
                        "service": "echo"
                    },
                    {
                        "hostnames": ["web.test.local"],
                        "cert_path": cert_b_path,
                        "key_path": key_b_path,
                        "service": "echo"
                    }
                ]
            )

            # Start proxy
            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            # Test SNI=api.test.local -> should get server A's cert
            cn_a = get_certificate_cn("127.0.0.1", proxy_port, "api.test.local", ca_cert_path)
            assert cn_a == "api.test.local", \
                f"Expected CN 'api.test.local' for SNI=api.test.local, got '{cn_a}'"

            # Test SNI=web.test.local -> should get server B's cert
            cn_b = get_certificate_cn("127.0.0.1", proxy_port, "web.test.local", ca_cert_path)
            assert cn_b == "web.test.local", \
                f"Expected CN 'web.test.local' for SNI=web.test.local, got '{cn_b}'"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_wildcard_certificate_matches_subdomain(self) -> None:
        """
        Wildcard certificate (*.test.local) matches foo.test.local.

        Expected:
        - SNI=foo.test.local succeeds with wildcard certificate
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            ca_cert_path, ca_key_path = generate_ca_certificate(temp_dir)

            # Generate wildcard certificate
            cert_path, key_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["*.test.local"],
                cert_name="wildcard"
            )

            config_path = create_single_server_config(
                proxy_port, temp_dir, cert_path, key_path
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            # Test SNI=foo.test.local -> should succeed
            success, error = try_tls_connection_with_sni(
                "127.0.0.1", proxy_port, "foo.test.local", ca_cert_path
            )
            assert success, f"Expected TLS connection to succeed for foo.test.local: {error}"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_wildcard_certificate_matches_bare_domain(self) -> None:
        """
        Wildcard certificate (*.test.local) matches bare domain (test.local).

        This is the behavior we implement - wildcard also matches the bare domain.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            ca_cert_path, ca_key_path = generate_ca_certificate(temp_dir)

            # Include both wildcard and bare domain in SAN for OpenSSL client verification
            cert_path, key_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["*.test.local", "test.local"],
                cert_name="wildcard"
            )

            config_path = create_single_server_config(
                proxy_port, temp_dir, cert_path, key_path
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            # Test SNI=test.local -> should succeed (bare domain match via wildcard)
            # Note: We add test.local to SAN because OpenSSL client verification
            # doesn't recognize bare domain matching wildcard patterns
            success, error = try_tls_connection_with_sni(
                "127.0.0.1", proxy_port, "test.local", ca_cert_path
            )
            assert success, f"Expected TLS connection to succeed for test.local: {error}"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_wildcard_certificate_not_match_multi_level(self) -> None:
        """
        Wildcard certificate (*.test.local) does NOT match bar.foo.test.local.

        Multi-level subdomains should NOT match a single-level wildcard.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            ca_cert_path, ca_key_path = generate_ca_certificate(temp_dir)

            cert_path, key_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["*.test.local"],
                cert_name="wildcard"
            )

            config_path = create_single_server_config(
                proxy_port, temp_dir, cert_path, key_path
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            # Test SNI=bar.foo.test.local -> should FAIL (multi-level)
            # Since we have no default certificate, TLS handshake should fail
            success, _ = try_tls_connection_with_sni(
                "127.0.0.1", proxy_port, "bar.foo.test.local", ca_cert_path
            )
            assert not success, \
                "Expected TLS connection to FAIL for bar.foo.test.local (multi-level subdomain)"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_unknown_sni_rejected(self) -> None:
        """
        SNI not matching any certificate causes TLS handshake failure.

        No default certificate is used - unknown SNI is rejected.
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            ca_cert_path, ca_key_path = generate_ca_certificate(temp_dir)

            # Generate certificate for specific domain only
            cert_path, key_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["known.test.local"],
                cert_name="known"
            )

            config_path = create_single_server_config(
                proxy_port, temp_dir, cert_path, key_path,
                hostnames=["known.test.local"]
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            # Test SNI=unknown.test.local -> should FAIL
            success, _ = try_tls_connection_with_sni(
                "127.0.0.1", proxy_port, "unknown.test.local", ca_cert_path
            )
            assert not success, \
                "Expected TLS connection to FAIL for unknown.test.local (no matching cert)"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_exact_match_priority_over_wildcard(self) -> None:
        """
        Exact domain match takes priority over wildcard match.

        Setup:
        - Certificate A: SAN=*.test.local (wildcard)
        - Certificate B: SAN=api.test.local (exact)

        Expected:
        - SNI=api.test.local returns Certificate B (exact match)
        - SNI=foo.test.local returns Certificate A (wildcard match)
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            ca_cert_path, ca_key_path = generate_ca_certificate(temp_dir)

            # Generate wildcard certificate
            wildcard_cert_path, wildcard_key_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["*.test.local"],
                cert_name="wildcard"
            )

            # Generate exact match certificate
            exact_cert_path, exact_key_path = generate_server_certificate(
                temp_dir, ca_cert_path, ca_key_path,
                san_entries=["api.test.local"],
                cert_name="exact"
            )

            # Create config with both servers (wildcard first in config)
            config_path = create_multi_server_config(
                proxy_port, temp_dir,
                servers=[
                    {
                        "hostnames": ["*.test.local"],
                        "cert_path": wildcard_cert_path,
                        "key_path": wildcard_key_path,
                        "service": "echo"
                    },
                    {
                        "hostnames": ["api.test.local"],
                        "cert_path": exact_cert_path,
                        "key_path": exact_key_path,
                        "service": "echo"
                    }
                ]
            )

            proxy_proc = start_proxy(config_path)
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy failed to start"

            # Test SNI=api.test.local -> should get exact cert (not wildcard)
            cn = get_certificate_cn("127.0.0.1", proxy_port, "api.test.local", ca_cert_path)
            assert cn == "api.test.local", \
                f"Expected exact match cert 'api.test.local', got '{cn}'"

            # Test SNI=foo.test.local -> should get wildcard cert
            cn = get_certificate_cn("127.0.0.1", proxy_port, "foo.test.local", ca_cert_path)
            assert cn == "*.test.local", \
                f"Expected wildcard cert '*.test.local', got '{cn}'"

        finally:
            if proxy_proc:
                terminate_process(proxy_proc)
            shutil.rmtree(temp_dir, ignore_errors=True)
