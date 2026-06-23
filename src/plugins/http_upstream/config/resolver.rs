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
use super::raw::{HttpUpstreamPluginConfig, QuicConfig};
use super::resolved::{
  Address, Protocol, ProtocolKind, QuicResolved, Upstream,
};
use super::validation::validate_address_format;
use crate::config::UserCredential;

/// Merge QUIC config at field level through three levels.
fn merge_quic_field_level(
  addr: Option<&QuicConfig>,
  upstream: Option<&QuicConfig>,
  plugin: Option<&QuicConfig>,
) -> QuicResolved {
  QuicResolved {
    max_idle_timeout: resolve_field(
      addr.and_then(|q| q.max_idle_timeout).as_ref(),
      upstream.and_then(|q| q.max_idle_timeout).as_ref(),
      plugin.and_then(|q| q.max_idle_timeout).as_ref(),
    ),
    keep_alive_interval: resolve_field_with_default(
      addr.map(|q| q.keep_alive_interval).as_ref(),
      upstream.map(|q| q.keep_alive_interval).as_ref(),
      plugin.map(|q| q.keep_alive_interval).as_ref(),
      default_keep_alive_interval(),
    ),
    max_concurrent_bidi_streams: resolve_field(
      addr.and_then(|q| q.max_concurrent_bidi_streams).as_ref(),
      upstream.and_then(|q| q.max_concurrent_bidi_streams).as_ref(),
      plugin.and_then(|q| q.max_concurrent_bidi_streams).as_ref(),
    ),
    initial_mtu: resolve_field(
      addr.and_then(|q| q.initial_mtu).as_ref(),
      upstream.and_then(|q| q.initial_mtu).as_ref(),
      plugin.and_then(|q| q.initial_mtu).as_ref(),
    ),
    send_window: resolve_field(
      addr.and_then(|q| q.send_window).as_ref(),
      upstream.and_then(|q| q.send_window).as_ref(),
      plugin.and_then(|q| q.send_window).as_ref(),
    ),
    receive_window: resolve_field(
      addr.and_then(|q| q.receive_window).as_ref(),
      upstream.and_then(|q| q.receive_window).as_ref(),
      plugin.and_then(|q| q.receive_window).as_ref(),
    ),
  }
}

/// Resolve chain-mode configuration through three-level inheritance.
pub(crate) fn merge_chain_config(
  plugin: &HttpUpstreamPluginConfig,
) -> Result<HashMap<String, Upstream>> {
  let mut upstreams: HashMap<String, Upstream> = HashMap::new();

  for upstream in &plugin.upstreams {
    let mut addresses = Vec::new();

    for addr in &upstream.addresses {
      let proto = addr.protocol()?;

      // Protocol-agnostic fields: address -> upstream -> plugin -> default
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

      let resolved_protocol = match proto {
        ProtocolKind::Http => {
          let a = addr.http.as_ref();
          let u = upstream.http.as_ref();
          let p = plugin.http.as_ref();
          Protocol::Http {
            connect_timeout: resolve_field_with_default(
              a.and_then(|c| c.connect_timeout).as_ref(),
              u.and_then(|c| c.connect_timeout).as_ref(),
              p.and_then(|c| c.connect_timeout).as_ref(),
              default_connect_timeout(),
            ),
          }
        }
        ProtocolKind::Https => {
          let a = addr.https.as_ref();
          let u = upstream.https.as_ref();
          let p = plugin.https.as_ref();
          Protocol::Https {
            connect_timeout: resolve_field_with_default(
              a.and_then(|c| c.connect_timeout).as_ref(),
              u.and_then(|c| c.connect_timeout).as_ref(),
              p.and_then(|c| c.connect_timeout).as_ref(),
              default_connect_timeout(),
            ),
            tls_handshake_timeout: resolve_field_with_default(
              a.and_then(|c| c.tls_handshake_timeout).as_ref(),
              u.and_then(|c| c.tls_handshake_timeout).as_ref(),
              p.and_then(|c| c.tls_handshake_timeout).as_ref(),
              default_tls_handshake_timeout(),
            ),
          }
        }
        ProtocolKind::Http3 => {
          let a = addr.http3.as_ref();
          let u = upstream.http3.as_ref();
          let p = plugin.http3.as_ref();
          Protocol::Http3 {
            tls_handshake_timeout: resolve_field_with_default(
              a.and_then(|c| c.tls_handshake_timeout).as_ref(),
              u.and_then(|c| c.tls_handshake_timeout).as_ref(),
              p.and_then(|c| c.tls_handshake_timeout).as_ref(),
              default_tls_handshake_timeout(),
            ),
            quic: merge_quic_field_level(
              a.and_then(|c| c.quic.as_ref()),
              u.and_then(|c| c.quic.as_ref()),
              p.and_then(|c| c.quic.as_ref()),
            ),
          }
        }
      };

      validate_address_format(&addr.address)?;

      addresses.push(Address {
        address: addr.address.clone(),
        hostname: addr.hostname.clone(),
        weight: addr.weight,
        protocol: resolved_protocol,
        tunnel_idle_timeout,
        user,
      });
    }

    let pool_config = upstream.pool.clone().unwrap_or_default();

    let u_http = upstream.http.as_ref();
    let p_http = plugin.http.as_ref();
    let connect_timeout = resolve_field_with_default(
      u_http.and_then(|c| c.connect_timeout).as_ref(),
      p_http.and_then(|c| c.connect_timeout).as_ref(),
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
      upstream.dns_resolve_timeout.as_ref(),
      plugin.dns_resolve_timeout.as_ref(),
      None,
      default_dns_resolve_timeout(),
    );

    upstreams.insert(
      upstream.name.clone(),
      Upstream {
        addresses,
        pool_config,
        connect_timeout,
        tunnel_idle_timeout,
        dns_resolve_timeout,
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
