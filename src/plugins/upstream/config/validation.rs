//! module: plugins::upstream::config::validation
//! responsibility: validate upstream transport policy before
//! construction
//! public operations: validate_address_format,
//! validate_plugin_config
//! data entities: none
//! tests: validation_tests.rs

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use super::raw::{
  UpstreamAddressConfig, UpstreamConfig, UpstreamPluginConfig,
};

macro_rules! validate_transport_fields {
  ($config:expr, $location:expr) => {{
    for (name, value) in [
      ("tcp_connect_timeout", $config.tcp_connect_timeout),
      ("tls_handshake_timeout", $config.tls_handshake_timeout),
      (
        "quic_connection_connect_timeout",
        $config.quic_connection_connect_timeout,
      ),
      (
        "quic_connection_keep_alive_interval",
        $config.quic_connection_keep_alive_interval,
      ),
      (
        "quic_connection_idle_timeout",
        $config.quic_connection_idle_timeout,
      ),
    ] {
      validate_duration_positive(value, $location, name)?;
    }
    for (name, value) in [
      ("tcp_keep_alive_time", $config.tcp_keep_alive_time),
      ("tcp_keep_alive_interval", $config.tcp_keep_alive_interval),
    ] {
      if value.is_some_and(|duration| {
        duration.as_secs() == 0
          || duration.as_secs() > u64::from(u32::MAX)
      }) {
        bail!(
          "{} {} must fit a positive u32 number of seconds",
          $location,
          name
        );
      }
    }
    if $config.tcp_keep_alive_retries == Some(0) {
      bail!("tcp_keep_alive_retries must be positive");
    }
    validate_duration_positive(
      $config.address_fail_timeout,
      $location,
      "address_fail_timeout",
    )?;
    if let Some(value) = $config.quic_connection_idle_timeout
      && (value.as_millis() == 0
        || value.as_millis()
          > u128::from(quinn::VarInt::MAX.into_inner()))
    {
      bail!(
        "{} quic_connection_idle_timeout must fit a positive QUIC \
         millisecond value",
        $location
      );
    }
    if let Some(value) =
      $config.quic_connection_max_concurrent_bidi_streams
      && !(1..=1u64 << 60).contains(&value)
    {
      bail!(
        "{} quic_connection_max_concurrent_bidi_streams must be in \
         1..=2^60",
        $location
      );
    }
    if let Some(value) = $config.quic_connection_initial_mtu
      && !(1200..=9000).contains(&value)
    {
      bail!(
        "{} quic_connection_initial_mtu must be in 1200..=9000",
        $location
      );
    }
    if let Some(value) = $config.quic_connection_send_window
      && value.as_u64_checked().is_none_or(|bytes| bytes == 0)
    {
      bail!(
        "{} quic_connection_send_window must fit a positive u64 byte \
         count",
        $location
      );
    }
    if let Some(value) = $config.quic_connection_receive_window
      && value.as_u64_checked().is_none_or(|bytes| {
        bytes == 0 || quinn::VarInt::from_u64(bytes).is_err()
      })
    {
      bail!(
        "{} quic_connection_receive_window must fit a positive QUIC \
         variable integer",
        $location
      );
    }
    if let Some(value) = $config.quic_stream_receive_window
      && value.as_u64_checked().is_none_or(|bytes| {
        bytes == 0 || quinn::VarInt::from_u64(bytes).is_err()
      })
    {
      bail!(
        "{} quic_stream_receive_window must fit a positive QUIC \
         variable integer",
        $location
      );
    }
  }};
}

/// Validate that an address string has host:port format without DNS
/// resolution.
pub(crate) fn validate_address_format(s: &str) -> Result<()> {
  if s.contains('@') {
    bail!("address '{s}' must not contain userinfo");
  }

  let authority =
    s.parse::<http::uri::Authority>().with_context(|| {
      format!("address '{s}' is not a valid authority")
    })?;

  let authority = crate::http_authority::normalize(&authority)
    .map_err(|error| {
      anyhow!("address '{s}' has invalid authority: {error:?}")
    })?;

  let host = authority.host();
  if host.is_empty() {
    bail!("address '{s}' missing host");
  }

  let port = authority
    .port_u16()
    .ok_or_else(|| anyhow!("address '{s}' missing or invalid port"))?;
  if port == 0 {
    bail!("address '{s}' has invalid port 0");
  }

  Ok(())
}

pub(crate) fn validate_plugin_config(
  plugin: &UpstreamPluginConfig,
) -> Result<()> {
  validate_dns_servers(plugin.dns_servers.as_deref())?;
  validate_duration_positive(
    plugin.dns_refresh_retry_interval,
    "plugin",
    "dns_refresh_retry_interval",
  )?;
  let mut upstream_names: HashSet<&str> = HashSet::new();

  validate_duration_positive(
    plugin.tunnel_idle_timeout,
    "plugin",
    "tunnel_idle_timeout",
  )?;

  validate_duration_positive(
    plugin.upstream_request_timeout,
    "plugin",
    "upstream_request_timeout",
  )?;
  validate_duration_positive(
    plugin.dns_resolve_timeout,
    "plugin",
    "dns_resolve_timeout",
  )?;
  validate_transport_fields!(plugin, "plugin");

  for upstream in &plugin.upstreams {
    validate_upstream_config(upstream)?;
    if !upstream_names.insert(upstream.name.as_str()) {
      bail!("duplicate upstream name '{}'", upstream.name);
    }
  }

  Ok(())
}

fn validate_upstream_config(upstream: &UpstreamConfig) -> Result<()> {
  validate_duration_positive(
    upstream.tunnel_idle_timeout,
    &upstream.name,
    "tunnel_idle_timeout",
  )?;
  if let Some(pool) = &upstream.pool {
    validate_duration_positive(
      Some(pool.idle_timeout),
      &upstream.name,
      "pool.idle_timeout",
    )?;
  }
  validate_duration_positive(
    upstream.upstream_request_timeout,
    &upstream.name,
    "upstream_request_timeout",
  )?;
  validate_transport_fields!(upstream, &upstream.name);
  if upstream.name.is_empty() {
    bail!("upstream name must not be empty");
  }

  if upstream.addresses.is_empty() {
    if upstream.user.is_some() {
      bail!(
        "direct upstream '{}' must not configure upstream proxy user",
        upstream.name
      );
    }
    return Ok(());
  }

  for addr in &upstream.addresses {
    validate_address_config(&upstream.name, addr)?;
  }

  Ok(())
}

fn validate_dns_servers(
  servers: Option<&[std::net::SocketAddr]>,
) -> Result<()> {
  if let Some(servers) = servers
    && (servers.is_empty()
      || servers.iter().any(|server| server.port() == 0))
  {
    bail!(
      "dns_servers must contain at least one IP address with a \
       nonzero port"
    );
  }
  Ok(())
}

fn validate_address_config(
  upstream_name: &str,
  addr: &UpstreamAddressConfig,
) -> Result<()> {
  validate_duration_positive(
    addr.tunnel_idle_timeout,
    upstream_name,
    "tunnel_idle_timeout",
  )?;
  validate_duration_positive(
    addr.upstream_request_timeout,
    upstream_name,
    "upstream_request_timeout",
  )?;
  validate_transport_fields!(addr, upstream_name);
  validate_address_format(&addr.address)?;

  if addr.weight == 0 {
    bail!(
      "upstream '{upstream_name}' address '{}' weight must be greater \
       than 0",
      addr.address
    );
  }

  Ok(())
}

fn validate_duration_positive(
  value: Option<Duration>,
  location: &str,
  field: &str,
) -> Result<()> {
  if let Some(value) = value
    && (value.is_zero()
      || std::time::Instant::now().checked_add(value).is_none())
  {
    bail!("{location} {field} must be positive and representable");
  }
  Ok(())
}
