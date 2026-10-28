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
  default_connect_timeout, default_keep_alive_interval,
  default_tls_handshake_timeout, default_tunnel_idle_timeout,
};
use super::protocol::ProtocolKind;
use super::raw::UpstreamPluginConfig;
use super::resolved::{Address, Protocol, QuicResolved, Upstream};
use super::validation::validate_plugin_config;
use crate::config::UserCredential;

fn resolve_quic(
  pool: &super::connection_pool::ConnectionPoolConfig,
) -> QuicResolved {
  QuicResolved {
    max_idle_timeout: pool.quic_connection_idle_timeout,
    keep_alive_interval: pool
      .quic_connection_keep_alive_interval
      .unwrap_or_else(default_keep_alive_interval),
    max_concurrent_bidi_streams: pool
      .quic_connection_max_concurrent_bidi_streams,
    initial_mtu: pool.quic_connection_initial_mtu,
    send_window: pool.quic_connection_send_window.map(|v| v.as_u64()),
    receive_window: pool
      .quic_connection_receive_window
      .map(|v| v.as_u64()),
    stream_receive_window: pool
      .quic_stream_receive_window
      .map(|v| v.as_u64()),
  }
}
/// Resolve chain-mode configuration through three-level inheritance.
pub(crate) fn merge_chain_config(
  plugin: &UpstreamPluginConfig,
) -> Result<HashMap<String, Upstream>> {
  validate_plugin_config(plugin)?;
  let pools = super::connection_pool::resolve_connection_pools(plugin)?;
  let plugin_pool =
    plugin.use_connection_pool.as_deref().unwrap_or("default");
  if !pools.contains_key(plugin_pool) {
    anyhow::bail!("unknown connection pool {plugin_pool}");
  }

  let mut upstreams: HashMap<String, Upstream> = HashMap::new();

  for upstream in &plugin.upstreams {
    let pool_name =
      upstream.use_connection_pool.as_deref().unwrap_or(plugin_pool);
    let pool = pools.get(pool_name).ok_or_else(|| {
      anyhow::anyhow!("unknown connection pool {pool_name}")
    })?;
    let mut addresses = Vec::new();

    for addr in &upstream.addresses {
      let address_pool_name =
        addr.use_connection_pool.as_deref().unwrap_or(pool_name);
      let pool = pools.get(address_pool_name).ok_or_else(|| {
        anyhow::anyhow!("unknown connection pool {address_pool_name}")
      })?;
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
          connect_timeout: pool
            .tcp_connect_timeout
            .unwrap_or_else(default_connect_timeout),
        },
        ProtocolKind::Http => Protocol::Http {
          connect_timeout: pool
            .tcp_connect_timeout
            .unwrap_or_else(default_connect_timeout),
        },
        ProtocolKind::Https => Protocol::Https {
          connect_timeout: pool
            .tcp_connect_timeout
            .unwrap_or_else(default_connect_timeout),
          tls_handshake_timeout: pool
            .tls_handshake_timeout
            .unwrap_or_else(default_tls_handshake_timeout),
        },
        ProtocolKind::Http3 => Protocol::Http3 {
          tls_handshake_timeout: pool
            .quic_connection_connect_timeout
            .unwrap_or_else(default_tls_handshake_timeout),
          quic: resolve_quic(pool),
        },
      };

      addresses.push(Address {
        use_connection_pool: address_pool_name.to_owned(),
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
        tcp_keep_alive_time: pool.tcp_keep_alive_time,
        tcp_keep_alive_interval: pool.tcp_keep_alive_interval,
        tcp_keep_alive_retries: pool.tcp_keep_alive_retries,
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

    let connect_timeout =
      pool.tcp_connect_timeout.unwrap_or_else(default_connect_timeout);
    let tunnel_idle_timeout = resolve_field_with_default(
      upstream.tunnel_idle_timeout.as_ref(),
      plugin.tunnel_idle_timeout.as_ref(),
      None,
      default_tunnel_idle_timeout(),
    );

    upstreams.insert(
      upstream.name.clone(),
      Upstream {
        use_connection_pool: pool_name.to_owned(),
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
        tcp_keep_alive_time: pool.tcp_keep_alive_time,
        tcp_keep_alive_interval: pool.tcp_keep_alive_interval,
        tcp_keep_alive_retries: pool.tcp_keep_alive_retries,
        addresses,
        connect_timeout,
        tls_handshake_timeout: pool
          .tls_handshake_timeout
          .unwrap_or_else(default_tls_handshake_timeout),
        tunnel_idle_timeout,
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
