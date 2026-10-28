"""Default-user inheritance through a real HTTP/3 relay.

Explicit credentials, client certificates and rejections are covered by
chain_matrix_auth; simultaneous two-hop authentication by proxy_chain.
The former TLS override case only configured a single global CA and is
covered by successful TLS exchanges in chain_matrix_local.
"""

import shutil
import socket
import subprocess
import tempfile

from tests.fixtures.configuration import StringMap
from tests.fixtures.curl import get_curl_env_without_no_proxy
from tests.fixtures.h3_configuration import (
    create_http3_chain_config_with_per_proxy_auth,
    create_http3_listener_config_with_password_auth,
)
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server, one_shot_echo_handler


class TestHTTP3ChainAuthInheritance:
    """Test authentication inheritance scenarios."""

    def test_chain_inherits_default_auth(self, shared_test_certs: StringMap) -> None:
        """
        TC-CHAIN-AUTH-004: Proxy inherits user from default_user.

        Target: Verify proxy without user field inherits from default_user.
        """
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()

        http_port = get_unique_port()
        h3_port = get_unique_port()
        target_port = get_unique_port()

        chain_proc: BytesProcess | None = None
        h3_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            cert_path = shared_test_certs["cert_path"]
            key_path = shared_test_certs["key_path"]
            ca_path = shared_test_certs["ca_path"]

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, one_shot_echo_handler
            )

            h3_config = create_http3_listener_config_with_password_auth(
                proxy_port=h3_port,
                cert_path=cert_path,
                key_path=key_path,
                temp_dir=temp_dir1,
                users=[("inherited_user", "inherited_pass")],
            )
            h3_proc = start_proxy(h3_config)
            assert h3_proc.wait_ready()

            # Proxy has NO user field - should inherit from default_user
            chain_config = create_http3_chain_config_with_per_proxy_auth(
                http_port=http_port,
                proxy_group=[
                    ("127.0.0.1", h3_port, 1, None, None)
                ],  # No user specified
                ca_path=ca_path,
                temp_dir=temp_dir2,
                default_user=(
                    "inherited_user",
                    "inherited_pass",
                ),  # Will be inherited
            )
            chain_proc = start_proxy(chain_config)
            assert chain_proc.wait_ready()

            # Clear no_proxy to force proxy usage for localhost
            env = get_curl_env_without_no_proxy()
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-p",
                    "--http0.9",
                    "-x",
                    f"http://127.0.0.1:{http_port}",
                    f"http://127.0.0.1:{target_port}/",
                    "-d",
                    "test_inheritance",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "2",
                ],
                capture_output=True,
                text=True,
                env=env,
            )

            assert "test_inheritance" in result.stdout, (
                "Expected echo data (inheritance should work), got stdout:"
                + f" {result.stdout}, stderr: {result.stderr}"
            )

        finally:
            if chain_proc:
                chain_proc.kill()
                _ = chain_proc.wait(timeout=5)
            if h3_proc:
                h3_proc.kill()
                _ = h3_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir1, ignore_errors=True)
            shutil.rmtree(temp_dir2, ignore_errors=True)
