"""
Configuration builder utilities for integration tests.

This module provides functions to generate neoproxy YAML configuration files
for HTTP/3 listener and chain proxy test scenarios.
"""

import os

type WeightedProxy = tuple[str, int, int]
type BasicUser = tuple[str, str]
type AuthProxy = tuple[str, int, int, str | None, str | None]


def create_http3_listener_config(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str,
    auth_config: str | None = None,
    quic_config: str | None = None,
    server_threads: int = 1,
) -> str:
    """
    Create HTTP/3 Listener configuration file.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        temp_dir: Temporary directory for logs
        auth_config: Optional authentication config YAML string
        quic_config: Optional QUIC config YAML string
        server_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    # QUIC config goes in listener args
    quic_section = ""
    if quic_config:
        # Indent each line of quic_config so it nests under 'quic:'
        indented = "\n".join("      " + line.strip() for line in quic_config.strip().splitlines())
        quic_section = f"""
  args:
    quic:
{indented}"""

    config_content = f"""server_threads: {server_threads}

plugins:
  http_upstream:
    upstreams:
      - name: direct

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]{quic_section}

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  listeners: ["h3_main"]
  service: direct
"""
    config_path = os.path.join(temp_dir, "http3_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_chain_config(
    http_port: int,
    proxy_group: list[WeightedProxy],
    ca_path: str,
    temp_dir: str,
    server_threads: int = 1,
    upstream_name: str = "test_upstream",
) -> str:
    """
    Create HTTP/3 Chain service configuration file (new upstream format).

    Args:
        http_port: Port for the HTTP listener
        proxy_group: List of (address, port, weight) tuples
        ca_path: CA certificate path
        temp_dir: Temporary directory for logs
        server_threads: Number of worker threads
        upstream_name: Name for the upstream group

    Returns:
        str: Path to the configuration file
    """
    address_list: list[str] = []
    for addr, port, weight in proxy_group:
        address_list.append(
            f"          - address: {addr}:{port}\n"
            f"            hostname: localhost\n"
            f"            weight: {weight}\n"
            f"            http3: {{}}"
        )

    address_section = "\n".join(address_list)

    config_content = f"""server_threads: {server_threads}

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: {upstream_name}
        addresses:
{address_section}

listeners:
- name: http_main
  kind: http
  addresses: ["0.0.0.0:{http_port}"]

services:
- name: upstream
  kind: http_upstream.upstream
  args:
    upstream: {upstream_name}

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: upstream
"""
    config_path = os.path.join(temp_dir, "http3_chain_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_listener_config_with_password_auth(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str,
    users: list[BasicUser],
    quic_config: str | None = None,
    server_threads: int = 1,
) -> str:
    """
    Create HTTP/3 Listener configuration with password authentication.

    Uses NEW config format with server-level TLS and users.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        temp_dir: Temporary directory for logs
        users: List of (username, plaintext_password) tuples
        quic_config: Optional QUIC config YAML string
        server_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    user_lines: list[str] = []
    for username, password in users:
        user_lines.append(f'        - username: "{username}"')
        user_lines.append(f'          password: "{password}"')

    users_section = "\n".join(user_lines)

    listener_args_section = ""
    if quic_config:
        listener_args_section = f"""
  args:
    quic:
{quic_config}"""

    config_content = f"""server_threads: {server_threads}

plugins:
  http_upstream:
    upstreams:
      - name: direct
  auth:

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct
  layers:
    - kind: auth.basic_auth
      args:
        users:
{users_section}

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]{listener_args_section}

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
  listeners: ["h3_main"]
  service: direct
"""
    config_path = os.path.join(temp_dir, "http3_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_listener_config_with_tls_client_cert(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    client_ca_path: str,
    temp_dir: str,
    quic_config: str | None = None,
    server_threads: int = 1,
) -> str:
    """
    Create HTTP/3 Listener configuration with TLS client certificate auth.

    Uses NEW config format with server-level TLS including client_ca_certs.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        client_ca_path: Client CA certificate path
        temp_dir: Temporary directory for logs
        quic_config: Optional QUIC config YAML string
        server_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    listener_args_section = ""
    if quic_config:
        listener_args_section = f"""
  args:
    quic:
{quic_config}"""

    config_content = f"""server_threads: {server_threads}

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]{listener_args_section}

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
    client_ca_certs:
    - "{client_ca_path}"
  listeners: ["h3_main"]
  service: direct
"""
    config_path = os.path.join(temp_dir, "http3_tls_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_listener_config_with_mtls_and_password(
    proxy_port: int,
    cert_path: str,
    key_path: str,
    client_ca_path: str,
    temp_dir: str,
    users: list[BasicUser],
    quic_config: str | None = None,
    server_threads: int = 1,
) -> str:
    """
    Create HTTP/3 Listener configuration with BOTH TLS client cert AND password auth.

    Uses NEW config format with server-level TLS and users.

    This is used for testing dual-auth scenarios where BOTH mTLS and password
    must succeed. Transport layer (TLS client cert) is verified first,
    then application layer (password). Both must pass.

    Args:
        proxy_port: Port for the HTTP/3 listener
        cert_path: TLS certificate path
        key_path: TLS private key path
        client_ca_path: Client CA certificate path for mTLS
        temp_dir: Temporary directory for logs
        users: List of (username, plaintext_password) tuples for password auth
        quic_config: Optional QUIC config YAML string
        server_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    user_lines: list[str] = []
    for username, password in users:
        user_lines.append(f'        - username: "{username}"')
        user_lines.append(f'          password: "{password}"')

    users_section = "\n".join(user_lines)

    listener_args_section = ""
    if quic_config:
        listener_args_section = f"""
  args:
    quic:
{quic_config}"""

    config_content = f"""server_threads: {server_threads}

plugins:
  http_upstream:
    upstreams:
      - name: direct
  auth:

services:
- name: direct
  kind: http_upstream.upstream
  args:
    upstream: direct
  layers:
    - kind: auth.basic_auth
      args:
        users:
{users_section}

listeners:
- name: h3_main
  kind: http3
  addresses: ["0.0.0.0:{proxy_port}"]{listener_args_section}

servers:
- name: http3_server
  tls:
    certificates:
    - cert_path: "{cert_path}"
      key_path: "{key_path}"
    client_ca_certs:
    - "{client_ca_path}"
  listeners: ["h3_main"]
  service: direct
"""
    config_path = os.path.join(temp_dir, "http3_mtls_password_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


def create_http3_chain_config_with_per_proxy_auth(
    http_port: int,
    proxy_group: list[AuthProxy],
    ca_path: str,
    temp_dir: str,
    default_user: BasicUser | None = None,
    default_tls: str | None = None,
    server_threads: int = 1,
    upstream_name: str = "test_upstream",
) -> str:
    """
    Create HTTP/3 Chain service config with per-proxy auth (new upstream format).

    Args:
        http_port: Port for the HTTP listener
        proxy_group: List of (address, port, weight, user_yaml, tls_yaml) tuples.
                     user_yaml: YAML string for user credentials, can be None.
                     tls_yaml: YAML string for TLS config, can be None.
        ca_path: CA certificate path
        temp_dir: Temporary directory for logs
        default_user: Optional tuple of (username, password) for plugin-level user.
        default_tls: Optional YAML string for plugin-level tls extra fields.
        server_threads: Number of worker threads
        upstream_name: Name for the upstream group

    Returns:
        str: Path to the configuration file
    """

    # Helper: indent YAML block
    def indent(text: str, spaces: int) -> str:
        import textwrap

        dedented = textwrap.dedent(text)
        prefix = " " * spaces
        return "\n".join(prefix + line for line in dedented.strip().split("\n"))

    address_list: list[str] = []
    # Per-address TLS is now global; collect any tls_yaml to merge into
    # plugin-level certificates
    collected_tls_yaml: str | None = None
    for addr, port, weight, user_yaml, tls_yaml in proxy_group:
        # Build address-level user section
        user_section = ""
        if user_yaml:
            user_section = f"\n            user:\n{indent(user_yaml, 14)}"
        if tls_yaml:
            collected_tls_yaml = tls_yaml  # Use last non-None tls_yaml

        entry = (
            f"          - address: {addr}:{port}\n"
            f"            hostname: localhost\n"
            f"            weight: {weight}{user_section}\n"
            f"            http3: {{}}"
        )
        address_list.append(entry)

    address_section = "\n".join(address_list)

    # Plugin-level user (goes inside upstream defaults)
    plugin_user_section = ""
    if default_user:
        plugin_user_section = f'    user:\n      username: "{default_user[0]}"\n      password: "{default_user[1]}"\n'

    # Plugin-level tls (global certificates: server_ca_path + optional client certs)
    # Merge default_tls and any per-address tls_yaml into the global certificates
    effective_tls = default_tls or collected_tls_yaml
    plugin_tls_section = ""
    if effective_tls:
        plugin_tls_section = f'    certificates:\n      server_ca_path: "{ca_path}"\n{indent(effective_tls, 6)}\n'
    else:
        plugin_tls_section = f'    certificates:\n      server_ca_path: "{ca_path}"\n'

    config_content = f"""server_threads: {server_threads}

plugins:
  http_upstream:
{plugin_user_section}{plugin_tls_section}    upstreams:
      - name: {upstream_name}
        addresses:
{address_section}

listeners:
- name: http_main
  kind: http
  addresses: [ "0.0.0.0:{http_port}" ]

services:
- name: upstream
  kind: http_upstream.upstream
  args:
    upstream: {upstream_name}

servers:
- name: http_proxy
  listeners: ["http_main"]
  service: upstream
"""
    config_path = os.path.join(temp_dir, "http3_chain_auth_config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path
