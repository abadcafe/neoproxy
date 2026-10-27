//! module: plugins::upstream::config::resolver
//! responsibility: resolve upstream policy inheritance
//! public operations: merge_chain_config
//! data entities: none
//! tests: resolver_tests.rs

use std::collections::HashMap;

use anyhow::Result;

use super::super::inherit::{
  resolve_field, resolve_field_with_default,
};
use super::defaults::{
  default_connect_timeout, default_dns_resolve_timeout,
  default_keep_alive_interval, default_tls_handshake_timeout,
  default_tunnel_idle_timeout,
};
use super::protocol::ProtocolKind;
use super::raw::UpstreamPluginConfig;
use super::resolved::{Address, Protocol, QuicResolved, Upstream};
use super::validation::validate_plugin_config;
use crate::config::UserCredential;

fn merge_quic_field_level(
  addr: Option<&super::raw::UpstreamAddressConfig>,
  upstream: &super::raw::UpstreamConfig,
  plugin: &UpstreamPluginConfig,
) -> QuicResolved {
  QuicResolved {
    max_idle_timeout: resolve_field(
      addr.and_then(|c| c.quic_connection_idle_timeout).as_ref(),
      upstream.quic_connection_idle_timeout.as_ref(),
      plugin.quic_connection_idle_timeout.as_ref(),
    ),
    keep_alive_interval: resolve_field_with_default(
      addr.and_then(|c| c.quic_connection_keep_alive_interval).as_ref(),
      upstream.quic_connection_keep_alive_interval.as_ref(),
      plugin.quic_connection_keep_alive_interval.as_ref(),
      default_keep_alive_interval(),
    ),
    max_concurrent_bidi_streams: resolve_field(
      addr
        .and_then(|c| c.quic_connection_max_concurrent_bidi_streams)
        .as_ref(),
      upstream.quic_connection_max_concurrent_bidi_streams.as_ref(),
      plugin.quic_connection_max_concurrent_bidi_streams.as_ref(),
    ),
    initial_mtu: resolve_field(
      addr.and_then(|c| c.quic_connection_initial_mtu).as_ref(),
      upstream.quic_connection_initial_mtu.as_ref(),
      plugin.quic_connection_initial_mtu.as_ref(),
    ),
    send_window: resolve_field(
      addr.and_then(|c| c.quic_connection_send_window).as_ref(),
      upstream.quic_connection_send_window.as_ref(),
      plugin.quic_connection_send_window.as_ref(),
    ),
    receive_window: resolve_field(
      addr.and_then(|c| c.quic_connection_receive_window).as_ref(),
      upstream.quic_connection_receive_window.as_ref(),
      plugin.quic_connection_receive_window.as_ref(),
    ),
  }
}

/// Resolve chain-mode configuration through three-level inheritance.
pub(crate) fn merge_chain_config(
  plugin: &UpstreamPluginConfig,
) -> Result<HashMap<String, Upstream>> {
  validate_plugin_config(plugin)?;

  let mut upstreams: HashMap<String, Upstream> = HashMap::new();

  for upstream in &plugin.upstreams {
    let mut addresses = Vec::new();

    for addr in &upstream.addresses {
      let proto = resolve_field(
        addr.address_protocol.as_ref(),
        upstream.address_protocol.as_ref(),
        plugin.address_protocol.as_ref(),
      )
      .unwrap_or(addr.address_protocol()?);

      // Protocol-agnostic fields: address -> upstream -> plugin ->
      // default
      let tunnel_idle_timeout = resolve_field_with_default(
        addr.tunnel_idle_timeout.as_ref(),
        upstream.tunnel_idle_timeout.as_ref(),
        plugin.tunnel_idle_timeout.as_ref(),
        default_tunnel_idle_timeout(),
      );
      let user = resolve_user(
        addr.user.as_ref(),
        upstream.user.as_ref(),
        plugin.user.as_ref(),
      );

      if proto == ProtocolKind::Socks5
        && let Some(user) = &user
        && (!(1..=255).contains(&user.username().len())
          || !(1..=255).contains(&user.password().len()))
      {
        anyhow::bail!(
          "SOCKS5 username and password must each contain 1..=255 \
           bytes"
        );
      }

      let resolved_protocol = match proto {
        ProtocolKind::Socks5 => Protocol::Socks5 {
          connect_timeout: resolve_field_with_default(
            addr.tcp_connect_timeout.as_ref(),
            upstream.tcp_connect_timeout.as_ref(),
            plugin.tcp_connect_timeout.as_ref(),
            default_connect_timeout(),
          ),
        },
        ProtocolKind::Http => Protocol::Http {
          connect_timeout: resolve_field_with_default(
            addr.tcp_connect_timeout.as_ref(),
            upstream.tcp_connect_timeout.as_ref(),
            plugin.tcp_connect_timeout.as_ref(),
            default_connect_timeout(),
          ),
        },
        ProtocolKind::Https => Protocol::Https {
          connect_timeout: resolve_field_with_default(
            addr.tcp_connect_timeout.as_ref(),
            upstream.tcp_connect_timeout.as_ref(),
            plugin.tcp_connect_timeout.as_ref(),
            default_connect_timeout(),
          ),
          tls_handshake_timeout: resolve_field_with_default(
            addr.tls_handshake_timeout.as_ref(),
            upstream.tls_handshake_timeout.as_ref(),
            plugin.tls_handshake_timeout.as_ref(),
            default_tls_handshake_timeout(),
          ),
        },
        ProtocolKind::Http3 => Protocol::Http3 {
          tls_handshake_timeout: resolve_field_with_default(
            addr.quic_connection_connect_timeout.as_ref(),
            upstream.quic_connection_connect_timeout.as_ref(),
            plugin.quic_connection_connect_timeout.as_ref(),
            default_tls_handshake_timeout(),
          ),
          quic: merge_quic_field_level(Some(addr), upstream, plugin),
        },
      };

      addresses.push(Address {
        address_max_fails: resolve_field_with_default(
          addr.address_max_fails.as_ref(),
          upstream.address_max_fails.as_ref(),
          plugin.address_max_fails.as_ref(),
          1,
        ),
        address_fail_timeout: resolve_field_with_default(
          addr.address_fail_timeout.as_ref(),
          upstream.address_fail_timeout.as_ref(),
          plugin.address_fail_timeout.as_ref(),
          std::time::Duration::from_secs(10),
        ),
        tcp_keep_alive_time: resolve_field(
          addr.tcp_keep_alive_time.as_ref(),
          upstream.tcp_keep_alive_time.as_ref(),
          plugin.tcp_keep_alive_time.as_ref(),
        ),
        tcp_keep_alive_interval: resolve_field(
          addr.tcp_keep_alive_interval.as_ref(),
          upstream.tcp_keep_alive_interval.as_ref(),
          plugin.tcp_keep_alive_interval.as_ref(),
        ),
        tcp_keep_alive_retries: resolve_field(
          addr.tcp_keep_alive_retries.as_ref(),
          upstream.tcp_keep_alive_retries.as_ref(),
          plugin.tcp_keep_alive_retries.as_ref(),
        ),
        address: addr.address.clone(),
        hostname: addr.hostname.clone(),
        weight: addr.weight,
        address_protocol: resolved_protocol,
        tunnel_idle_timeout,
        upstream_request_timeout: resolve_field_with_default(
          addr.upstream_request_timeout.as_ref(),
          upstream.upstream_request_timeout.as_ref(),
          plugin.upstream_request_timeout.as_ref(),
          std::time::Duration::from_secs(30),
        ),
        user,
      });
    }

    let pool_config = upstream.pool.clone().unwrap_or_default();

    let connect_timeout = resolve_field_with_default(
      upstream.tcp_connect_timeout.as_ref(),
      plugin.tcp_connect_timeout.as_ref(),
      None,
      default_connect_timeout(),
    );
    let tunnel_idle_timeout = resolve_field_with_default(
      upstream.tunnel_idle_timeout.as_ref(),
      plugin.tunnel_idle_timeout.as_ref(),
      None,
      default_tunnel_idle_timeout(),
    );
    let dns_resolve_timeout = resolve_field_with_default(
      plugin.dns_resolve_timeout.as_ref(),
      None,
      None,
      default_dns_resolve_timeout(),
    );

    upstreams.insert(
      upstream.name.clone(),
      Upstream {
        address_max_fails: resolve_field_with_default(
          upstream.address_max_fails.as_ref(),
          plugin.address_max_fails.as_ref(),
          None,
          1,
        ),
        address_fail_timeout: resolve_field_with_default(
          upstream.address_fail_timeout.as_ref(),
          plugin.address_fail_timeout.as_ref(),
          None,
          std::time::Duration::from_secs(10),
        ),
        tcp_keep_alive_time: resolve_field(
          upstream.tcp_keep_alive_time.as_ref(),
          plugin.tcp_keep_alive_time.as_ref(),
          None,
        ),
        tcp_keep_alive_interval: resolve_field(
          upstream.tcp_keep_alive_interval.as_ref(),
          plugin.tcp_keep_alive_interval.as_ref(),
          None,
        ),
        tcp_keep_alive_retries: resolve_field(
          upstream.tcp_keep_alive_retries.as_ref(),
          plugin.tcp_keep_alive_retries.as_ref(),
          None,
        ),
        dns_refresh_retry_interval: plugin
          .dns_refresh_retry_interval
          .unwrap_or(std::time::Duration::from_secs(30)),
        dns_servers: plugin.dns_servers.clone(),
        addresses,
        pool_config,
        connect_timeout,
        tls_handshake_timeout: resolve_field_with_default(
          upstream.tls_handshake_timeout.as_ref(),
          plugin.tls_handshake_timeout.as_ref(),
          None,
          default_tls_handshake_timeout(),
        ),
        tunnel_idle_timeout,
        dns_resolve_timeout,
        upstream_request_timeout: resolve_field_with_default(
          upstream.upstream_request_timeout.as_ref(),
          plugin.upstream_request_timeout.as_ref(),
          None,
          std::time::Duration::from_secs(30),
        ),
      },
    );
  }

  Ok(upstreams)
}

fn resolve_user(
  addr: Option<&UserCredential>,
  upstream: Option<&UserCredential>,
  plugin: Option<&UserCredential>,
) -> Option<UserCredential> {
  resolve_field(addr, upstream, plugin)
}
