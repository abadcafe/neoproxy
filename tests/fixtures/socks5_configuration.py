"""socks5 configuration fixture interface.
Tests: process and protocol consumers.
"""

import os

type UserConfig = dict[str, str]


def create_socks5_config(
    proxy_port: int,
    temp_dir: str,
    auth_type: str | None = None,
    users: list[UserConfig] | None = None,
    addresses: list[str] | None = None,
    header_read_timeout: str | None = None,
    server_threads: int = 1,
) -> str:
    """
    Create SOCKS5 listener configuration file.

    Args:
        proxy_port: Port for the SOCKS5 listener
        temp_dir: Temporary directory for logs
        auth_type: Authentication type ("password" or None for no auth)
        users: List of user dicts with "username" and "password" keys
        addresses: List of addresses to listen on (default: ["0.0.0.0:port"])
        header_read_timeout: Total request header timeout (default: "75s")
        server_threads: Number of worker threads

    Returns:
        str: Path to the configuration file
    """
    if addresses is None:
        addresses = [f"0.0.0.0:{proxy_port}"]

    # Build flat protocol fields for the listener
    args_entries: list[str] = []
    if header_read_timeout:
        args_entries.append(f'  header_read_timeout: "{header_read_timeout}"')

    addresses_yaml = "\n".join([f'  - "{a}"' for a in addresses])

    if args_entries:
        args_yaml = "\n" + "\n".join(args_entries)
    else:
        args_yaml = ""

    # Build auth layer for the service
    if auth_type == "password" and users:
        users_yaml_lines: list[str] = []
        for u in users:
            users_yaml_lines.append(f'        - username: "{u["username"]}"')
            users_yaml_lines.append(f'          password: "{u["password"]}"')
        layers_yaml = (
            "\n  layers:\n    - kind: auth.basic_auth\n      users:\n"
            + "\n".join(users_yaml_lines)
        )
    else:
        layers_yaml = ""

    auth_plugin_line = "\n  auth:" if (auth_type == "password" and users) else ""

    config_content = f"""server_threads: {server_threads}

plugins:
  upstream:
    upstreams:
      - name: direct{auth_plugin_line}

services:
- name: direct
  kind: upstream.upstream
  upstream: direct{layers_yaml}
listeners:
- name: socks5_main
  kind: socks5
  addresses:
{addresses_yaml}{args_yaml}

servers:
- name: socks5_server
  listeners: ["socks5_main"]
  service: direct
"""

    config_path = os.path.join(temp_dir, "socks5_config.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path
