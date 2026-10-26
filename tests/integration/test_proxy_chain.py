"""
Proxy chain integration tests.

Test target: Verify complete proxy chain with authentication at each layer.
Test nature: Black-box testing through external interface (curl).

Test matrix:
- HTTP(Password) -> HTTP/3(Password) -> Target
- HTTP(Password) -> HTTP/3(TLS Cert) -> Target
- SOCKS5(Password) -> HTTP/3(Password) -> Target
- SOCKS5(Password) -> HTTP/3(TLS Cert) -> Target

HTTP entries cover absolute-form HTTP/HTTPS GET and HEAD plus CONNECT to
HTTP/HTTPS origins. Local HTTP/HTTPS echo peers verify POST bodies in both
forwarding and tunneling modes. curl trace and http_connect verify the actual
request path; SOCKS5 entries exercise tunnels only.
"""

import shutil
import subprocess
import tempfile
from typing import Literal

import pytest

from tests.fixtures.chain_configuration import (
    create_entry_http_no_upstream_auth_config,
    create_entry_http_wrong_upstream_auth_config,
    create_entry_socks5_no_upstream_auth_config,
    create_upstream_no_auth_config,
    create_upstream_password_config,
)
from tests.fixtures.chain_scenario import (
    ChainRequest,
    is_proxy_auth_response,
    run_proxy_chain_test,
)
from tests.fixtures.configuration import StringMap
from tests.fixtures.ports import (
    get_unique_port,
    wait_for_proxy,
    wait_for_udp_port_bound,
)
from tests.fixtures.proxy_process import BytesProcess, start_proxy

type TargetScheme = Literal["http", "https"]

_BAIDU_HTTP_REQUESTS = [
    pytest.param(ChainRequest(mode="forward", scheme="http"), id="forward-http-get"),
    pytest.param(ChainRequest(mode="forward", scheme="https"), id="forward-https-get"),
    pytest.param(
        ChainRequest(mode="forward", scheme="http", method="HEAD"),
        id="forward-http-head",
    ),
    pytest.param(
        ChainRequest(mode="forward", scheme="https", method="HEAD"),
        id="forward-https-head",
    ),
    pytest.param(ChainRequest(mode="tunnel", scheme="http"), id="connect-http-get"),
    pytest.param(ChainRequest(mode="tunnel", scheme="https"), id="connect-https-get"),
]

_MOCK_HTTP_REQUESTS = [
    pytest.param(
        ChainRequest(mode="forward", scheme="http", method="POST"),
        id="forward-http-post",
    ),
    pytest.param(
        ChainRequest(mode="forward", scheme="https", method="POST"),
        id="forward-https-post",
    ),
    pytest.param(
        ChainRequest(mode="tunnel", scheme="http", method="POST"),
        id="connect-http-post",
    ),
    pytest.param(
        ChainRequest(mode="tunnel", scheme="https", method="POST"),
        id="connect-https-post",
    ),
]

# ==============================================================================
# Configuration helper functions
# ==============================================================================


# ==============================================================================
# Target Server Helper
# ==============================================================================


# ==============================================================================
# Common Test Runner
# ==============================================================================


# ==============================================================================
# Test classes - HTTP(Password) -> HTTP/3(Password) -> Target
# ==============================================================================


class TestProxyChainHTTPToHTTP3Password:
    """HTTP(Password) -> HTTP/3(Password) -> Target"""

    @pytest.mark.parametrize("case", _BAIDU_HTTP_REQUESTS)
    def test_to_baidu(self, shared_test_certs: StringMap, case: ChainRequest) -> None:
        """TC-CHAIN-PWD-001: HTTP(password)->HTTP/3(password)->baidu.com."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="password",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            case=case,
        )

    @pytest.mark.parametrize("case", _MOCK_HTTP_REQUESTS)
    def test_to_mock(self, shared_test_certs: StringMap, case: ChainRequest) -> None:
        """TC-CHAIN-PWD-002: HTTP(password)->HTTP/3(password)->mock echo."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="password",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            case=case,
        )


# ==============================================================================
# Test classes - HTTP(Password) -> HTTP/3(TLS Cert) -> Target
# ==============================================================================


class TestProxyChainHTTPToHTTP3TlsCert:
    """HTTP(Password) -> HTTP/3(TLS Cert) -> Target"""

    @pytest.mark.parametrize("case", _BAIDU_HTTP_REQUESTS)
    def test_to_baidu(
        self,
        shared_test_certs: StringMap,
        shared_client_cert: StringMap,
        case: ChainRequest,
    ) -> None:
        """TC-CHAIN-TLS-001: HTTP(password)->HTTP/3(TLS cert)->baidu.com."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="tls_cert",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            shared_client_cert=shared_client_cert,
            case=case,
        )

    @pytest.mark.parametrize("case", _MOCK_HTTP_REQUESTS)
    def test_to_mock(
        self,
        shared_test_certs: StringMap,
        shared_client_cert: StringMap,
        case: ChainRequest,
    ) -> None:
        """TC-CHAIN-TLS-002: HTTP(password)->HTTP/3(TLS cert)->mock echo."""
        run_proxy_chain_test(
            entry_type="http",
            upstream_auth="tls_cert",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            shared_client_cert=shared_client_cert,
            case=case,
        )


# ==============================================================================
# Test classes - SOCKS5(Password) -> HTTP/3(Password) -> Target
# ==============================================================================


class TestProxyChainSocks5ToHTTP3Password:
    """SOCKS5(Password) -> HTTP/3(Password) -> Target"""

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_to_baidu(self, shared_test_certs: StringMap, scheme: TargetScheme) -> None:
        """SOCKS5 tunnel carries an HTTP or HTTPS GET through authenticated H3."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="password",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            case=ChainRequest(scheme=scheme),
        )

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_to_mock(self, shared_test_certs: StringMap, scheme: TargetScheme) -> None:
        """TC-CHAIN-S5-PWD-002: SOCKS5(password)->HTTP/3(password)->mock echo."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="password",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            case=ChainRequest(scheme=scheme, method="POST"),
        )


# ==============================================================================
# Test classes - SOCKS5(Password) -> HTTP/3(TLS Cert) -> Target
# ==============================================================================


class TestProxyChainSocks5ToHTTP3TlsCert:
    """SOCKS5(Password) -> HTTP/3(TLS Cert) -> Target"""

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_to_baidu(
        self,
        shared_test_certs: StringMap,
        shared_client_cert: StringMap,
        scheme: TargetScheme,
    ) -> None:
        """TC-CHAIN-S5-TLS-001: SOCKS5(password)->HTTP/3(TLS cert)->baidu.com."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="tls_cert",
            target_type="baidu",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=None,
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            shared_client_cert=shared_client_cert,
            case=ChainRequest(scheme=scheme),
        )

    @pytest.mark.parametrize("scheme", ["http", "https"])
    def test_to_mock(
        self,
        shared_test_certs: StringMap,
        shared_client_cert: StringMap,
        scheme: TargetScheme,
    ) -> None:
        """TC-CHAIN-S5-TLS-002: SOCKS5(password)->HTTP/3(TLS cert)->mock echo."""
        run_proxy_chain_test(
            entry_type="socks5",
            upstream_auth="tls_cert",
            target_type="mock",
            http_port=get_unique_port(),
            h3_port=get_unique_port(),
            target_port=get_unique_port(),
            temp_dir1=tempfile.mkdtemp(),
            temp_dir2=tempfile.mkdtemp(),
            shared_test_certs=shared_test_certs,
            shared_client_cert=shared_client_cert,
            case=ChainRequest(scheme=scheme, method="POST"),
        )


# ==============================================================================
# Negative authentication tests (SR-006)
# ==============================================================================


class TestNegativeAuthHTTPEntry:
    """Negative tests for HTTP entry proxy authentication."""

    def test_http_entry_missing_auth_returns_407(
        self, shared_test_certs: StringMap
    ) -> None:
        """TC-NEG-AUTH-001: HTTP entry without Proxy-Authorization returns 407.

        When a proxy requires password authentication and the client sends
        a request without Proxy-Authorization header, the proxy must respond
        with 407 Proxy Authentication Required.

        NOTE: Target is www.baidu.com. This is NOT a network/DNS issue —
        the proxy returns 407 before any upstream connection is attempted.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: BytesProcess | None = None
        entry_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Start upstream HTTP/3 without auth (entry auth is what we test)
            upstream_config = create_upstream_no_auth_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), (
                "Upstream HTTP/3 listener failed to start"
            )

            # Start entry HTTP with password auth
            entry_config = create_entry_http_no_upstream_auth_config(
                http_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), (
                "Entry HTTP listener failed to start"
            )

            # Send CONNECT request without Proxy-Authorization.
            # For HTTPS through HTTP proxy (CONNECT tunnel), curl reports
            # exit code 56 and "response 407" in stderr when proxy returns 407.
            # Note: do NOT use -s flag, otherwise curl suppresses the 407
            # message from stderr.
            result = subprocess.run(
                [
                    "curl",
                    "-x",
                    f"http://127.0.0.1:{http_port}",
                    "https://www.baidu.com",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--connect-timeout",
                    "5",
                ],
                capture_output=True,
                text=True,
            )

            assert is_proxy_auth_response(result), (
                f"Expected 407 response, got http_code={result.stdout}, "
                + f"returncode={result.returncode}, stderr={result.stderr}"
            )

        finally:
            if entry_proc:
                entry_proc.kill()
                _ = entry_proc.wait(timeout=5)
            if upstream_proc:
                upstream_proc.kill()
                _ = upstream_proc.wait(timeout=5)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)

    def test_http_entry_wrong_credentials_returns_407(
        self, shared_test_certs: StringMap
    ) -> None:
        """TC-NEG-AUTH-002: HTTP entry with wrong credentials returns 407.

        When a proxy requires password authentication and the client sends
        incorrect credentials in the Proxy-Authorization header, the proxy
        must respond with 407 Proxy Authentication Required.

        NOTE: Target is www.baidu.com. This is NOT a network/DNS issue —
        the proxy returns 407 before any upstream connection is attempted.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: BytesProcess | None = None
        entry_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Start upstream HTTP/3 without auth (entry auth is what we test)
            upstream_config = create_upstream_no_auth_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), (
                "Upstream HTTP/3 listener failed to start"
            )

            # Start entry HTTP with password auth
            entry_config = create_entry_http_no_upstream_auth_config(
                http_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), (
                "Entry HTTP listener failed to start"
            )

            # Send request with wrong credentials.
            # For CONNECT tunnels, curl reports exit code 56 + "response 407".
            # Note: do NOT use -s flag, otherwise curl suppresses the 407
            # message from stderr.
            result = subprocess.run(
                [
                    "curl",
                    "-x",
                    f"http://wrong_user:wrong_pass@127.0.0.1:{http_port}",
                    "https://www.baidu.com",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--connect-timeout",
                    "5",
                ],
                capture_output=True,
                text=True,
            )

            assert is_proxy_auth_response(result), (
                f"Expected 407 response, got http_code={result.stdout}, "
                + f"returncode={result.returncode}, stderr={result.stderr}"
            )

        finally:
            if entry_proc:
                entry_proc.kill()
                _ = entry_proc.wait(timeout=5)
            if upstream_proc:
                upstream_proc.kill()
                _ = upstream_proc.wait(timeout=5)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


class TestNegativeAuthSOCKS5Entry:
    """Negative tests for SOCKS5 entry proxy authentication."""

    def test_socks5_entry_wrong_credentials_fails(
        self, shared_test_certs: StringMap
    ) -> None:
        """TC-NEG-AUTH-003: SOCKS5 entry with wrong credentials fails.

        When a SOCKS5 proxy has auth middleware and the client
        sends incorrect credentials, the auth middleware rejects
        the request and the connection fails.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        socks5_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: BytesProcess | None = None
        entry_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Start upstream HTTP/3 without auth (entry auth is what we test)
            upstream_config = create_upstream_no_auth_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), (
                "Upstream HTTP/3 listener failed to start"
            )

            # Start entry SOCKS5 with password auth
            entry_config = create_entry_socks5_no_upstream_auth_config(
                socks5_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", socks5_port, timeout=5.0), (
                "Entry SOCKS5 listener failed to start"
            )

            # Send request with wrong SOCKS5 credentials
            result = subprocess.run(
                [
                    "curl",
                    "--socks5-basic",
                    "--socks5-hostname",
                    f"127.0.0.1:{socks5_port}",
                    "--proxy-user",
                    "wrong_user:wrong_pass",
                    "https://www.baidu.com",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--connect-timeout",
                    "5",
                ],
                capture_output=True,
                text=True,
            )

            # SOCKS5 rejects wrong credentials during RFC 1929 subnegotiation;
            # curl reports authentication failure.
            # or a non-200 HTTP code depending on curl version.
            # The important thing is it does NOT return 200.
            assert result.stdout != "200", (
                "Expected non-200 response for wrong SOCKS5 credentials, got"
                + f" {result.stdout}. stderr: {result.stderr}"
            )

        finally:
            if entry_proc:
                entry_proc.kill()
                _ = entry_proc.wait(timeout=5)
            if upstream_proc:
                upstream_proc.kill()
                _ = upstream_proc.wait(timeout=5)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)


class TestNegativeAuthUpstream:
    """Negative tests for upstream proxy authentication."""

    def test_wrong_upstream_credentials_connection_fails(
        self, shared_test_certs: StringMap
    ) -> None:
        """TC-NEG-AUTH-004: Wrong upstream credentials cause connection failure.

        When the http3_chain service is configured with wrong credentials for
        the upstream proxy, the CONNECT request to the upstream should be
        rejected, and the client should receive a non-200 response.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()

        upstream_proc: BytesProcess | None = None
        entry_proc: BytesProcess | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            # Start upstream HTTP/3 WITH password auth (user1:pass1)
            upstream_config = create_upstream_password_config(
                h3_port, cert_path, key_path, temp_dir1
            )
            upstream_proc = start_proxy(upstream_config)
            assert wait_for_udp_port_bound("127.0.0.1", h3_port, timeout=5.0), (
                "Upstream HTTP/3 listener failed to start"
            )

            # Start entry HTTP with WRONG upstream credentials (wrong_user:wrong_pass)
            entry_config = create_entry_http_wrong_upstream_auth_config(
                http_port, h3_port, ca_path, temp_dir2
            )
            entry_proc = start_proxy(entry_config)
            assert wait_for_proxy("127.0.0.1", http_port, timeout=5.0), (
                "Entry HTTP listener failed to start"
            )

            # Send request with correct entry credentials but wrong upstream creds.
            # The upstream should reject the CONNECT request with 407,
            # which the entry proxy may forward back to the client or
            # report as a connection failure (502 Bad Gateway).
            result = subprocess.run(
                [
                    "curl",
                    "-x",
                    f"http://user1:pass1@127.0.0.1:{http_port}",
                    "https://www.baidu.com",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--connect-timeout",
                    "10",
                ],
                capture_output=True,
                text=True,
            )

            # The request must NOT succeed (non-200).
            # Depending on how http3_chain handles upstream auth failure,
            # we may see: 407 (forwarded), 502 (bad gateway), or curl error.
            http_code = result.stdout.strip()
            assert http_code != "200", (
                "Expected non-200 response for wrong upstream credentials, got"
                + f" {http_code}. stderr: {result.stderr}"
            )

        finally:
            if entry_proc:
                entry_proc.kill()
                _ = entry_proc.wait(timeout=5)
            if upstream_proc:
                upstream_proc.kill()
                _ = upstream_proc.wait(timeout=5)
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
