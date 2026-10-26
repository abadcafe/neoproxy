"""chain configuration fixture interface.
Tests: process and protocol consumers.
"""

import os


def create_upstream_password_config(
    h3_port: int,
    cert_path: str,
    key_path: str,
    temp_dir: str,
    *,
    target_ca_path: str | None = None,
) -> str:
    """Create upstream HTTP/3 config with password auth."""
    trust = (
        f'\n    certificates:\n      server_ca_path: "{target_ca_path}"'
        if target_ca_path is not None
        else ""
    )
    config_content = f"""server_threads: 1

plugins:
  http_upstream:{trust}
    upstreams:
      - name: direct
  auth:

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: h3_main
    kind: http3
    addresses: ["0.0.0.0:{h3_port}"]

servers:
  - name: upstream_http3
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
    listeners: ["h3_main"]
    service: tunnel
"""
    config_path = os.path.join(temp_dir, "upstream_password.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_upstream_tls_cert_config(
    h3_port: int,
    cert_path: str,
    key_path: str,
    client_ca_path: str,
    temp_dir: str,
    *,
    target_ca_path: str | None = None,
) -> str:
    """Create upstream HTTP/3 config with TLS client cert auth."""
    trust = (
        f'\n    certificates:\n      server_ca_path: "{target_ca_path}"'
        if target_ca_path is not None
        else ""
    )
    config_content = f"""server_threads: 1

plugins:
  http_upstream:{trust}
    upstreams:
      - name: direct

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct

listeners:
  - name: h3_main
    kind: http3
    addresses: ["0.0.0.0:{h3_port}"]

servers:
  - name: upstream_http3_tls
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
      client_ca_certs:
        - "{client_ca_path}"
    listeners: ["h3_main"]
    service: tunnel
"""
    config_path = os.path.join(temp_dir, "upstream_tls_cert.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_entry_http_password_config(
    http_port: int, h3_port: int, ca_path: str, temp_dir: str
) -> str:
    """Create entry HTTP config with password auth, connecting to password upstream."""
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: "127.0.0.1:{h3_port}"
            hostname: localhost
            weight: 1
            user:
              username: user1
              password: pass1
            http3: {{}}
  auth:

services:
  - name: proxy_chain
    kind: http_upstream.upstream
    args:
      upstream: test_upstream
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]

servers:
  - name: entry_http
    listeners: ["http_main"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_password.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_entry_http_tls_cert_config(
    http_port: int,
    h3_port: int,
    ca_path: str,
    client_cert_path: str,
    client_key_path: str,
    temp_dir: str,
) -> str:
    """Create entry HTTP config with password auth, connecting to TLS cert upstream."""
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      client_cert_path: "{client_cert_path}"
      client_key_path: "{client_key_path}"
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: "127.0.0.1:{h3_port}"
            hostname: localhost
            weight: 1
            http3: {{}}
  auth:

services:
  - name: proxy_chain
    kind: http_upstream.upstream
    args:
      upstream: test_upstream
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]

servers:
  - name: entry_http
    listeners: ["http_main"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_tls_cert.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_entry_socks5_password_config(
    socks5_port: int, h3_port: int, ca_path: str, temp_dir: str
) -> str:
    """
    Create entry SOCKS5 config with password auth, connecting to password upstream.
    """
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: "127.0.0.1:{h3_port}"
            hostname: localhost
            weight: 1
            user:
              username: user1
              password: pass1
            http3: {{}}
  auth:

services:
  - name: proxy_chain
    kind: http_upstream.upstream
    args:
      upstream: test_upstream
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: socks5_main
    kind: socks5
    addresses: ["127.0.0.1:{socks5_port}"]

servers:
  - name: entry_socks5
    listeners: ["socks5_main"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_socks5_password.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_entry_socks5_tls_cert_config(
    socks5_port: int,
    h3_port: int,
    ca_path: str,
    client_cert_path: str,
    client_key_path: str,
    temp_dir: str,
) -> str:
    """
    Create entry SOCKS5 config with password auth, connecting to TLS cert upstream.
    """
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      client_cert_path: "{client_cert_path}"
      client_key_path: "{client_key_path}"
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: "127.0.0.1:{h3_port}"
            hostname: localhost
            weight: 1
            http3: {{}}
  auth:

services:
  - name: proxy_chain
    kind: http_upstream.upstream
    args:
      upstream: test_upstream
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: socks5_main
    kind: socks5
    addresses:
      - "127.0.0.1:{socks5_port}"

servers:
  - name: entry_socks5
    service: proxy_chain
    listeners: ["socks5_main"]
"""
    config_path = os.path.join(temp_dir, "entry_socks5_tls_cert.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_entry_http_no_upstream_auth_config(
    http_port: int, h3_port: int, ca_path: str, temp_dir: str
) -> str:
    """Create entry HTTP config with password auth, no upstream auth."""
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: "127.0.0.1:{h3_port}"
            hostname: localhost
            weight: 1
            http3: {{}}
  auth:

services:
  - name: proxy_chain
    kind: http_upstream.upstream
    args:
      upstream: test_upstream
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]

servers:
  - name: entry_http
    listeners: ["http_main"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_no_upstream_auth.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_entry_socks5_no_upstream_auth_config(
    socks5_port: int, h3_port: int, ca_path: str, temp_dir: str
) -> str:
    """Create entry SOCKS5 config with password auth, no upstream auth."""
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: "127.0.0.1:{h3_port}"
            hostname: localhost
            weight: 1
            http3: {{}}
  auth:

services:
  - name: proxy_chain
    kind: http_upstream.upstream
    args:
      upstream: test_upstream
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: socks5_main
    kind: socks5
    addresses:
      - "127.0.0.1:{socks5_port}"

servers:
  - name: entry_socks5
    service: proxy_chain
    listeners: ["socks5_main"]
"""
    config_path = os.path.join(temp_dir, "entry_socks5_no_upstream_auth.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_entry_http_wrong_upstream_auth_config(
    http_port: int, h3_port: int, ca_path: str, temp_dir: str
) -> str:
    """Create entry HTTP config with password auth, wrong upstream credentials."""
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    certificates:
      server_ca_path: "{ca_path}"
    upstreams:
      - name: test_upstream
        addresses:
          - address: "127.0.0.1:{h3_port}"
            hostname: localhost
            weight: 1
            user:
              username: wrong_user
              password: wrong_pass
            http3: {{}}
  auth:

services:
  - name: proxy_chain
    kind: http_upstream.upstream
    args:
      upstream: test_upstream
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: user1
              password: pass1

listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:{http_port}"]

servers:
  - name: entry_http
    listeners: ["http_main"]
    service: proxy_chain
"""
    config_path = os.path.join(temp_dir, "entry_http_wrong_upstream_auth.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path


def create_upstream_no_auth_config(
    h3_port: int, cert_path: str, key_path: str, temp_dir: str
) -> str:
    """Create upstream HTTP/3 config without auth."""
    config_content = f"""server_threads: 1

plugins:
  http_upstream:
    upstreams:
      - name: direct

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct

listeners:
  - name: h3_main
    kind: http3
    addresses: ["0.0.0.0:{h3_port}"]

servers:
  - name: upstream_http3
    tls:
      certificates:
        - cert_path: "{cert_path}"
          key_path: "{key_path}"
    listeners: ["h3_main"]
    service: tunnel
"""
    config_path = os.path.join(temp_dir, "upstream_no_auth.yaml")
    with open(config_path, "w") as f:
        _ = f.write(config_content)
    return config_path
