use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use super::raw::{
  Http3ProtocolConfig, HttpUpstreamPluginConfig, QuicConfig,
  UpstreamAddressConfig, UpstreamConfig,
};

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
  plugin: &HttpUpstreamPluginConfig,
) -> Result<()> {
  let mut upstream_names: HashSet<&str> = HashSet::new();

  validate_http3_protocol_config(plugin.http3.as_ref(), "plugin")?;

  for upstream in &plugin.upstreams {
    validate_upstream_config(upstream)?;
    if !upstream_names.insert(upstream.name.as_str()) {
      bail!("duplicate upstream name '{}'", upstream.name);
    }
  }

  Ok(())
}

fn validate_upstream_config(upstream: &UpstreamConfig) -> Result<()> {
  if upstream.name.is_empty() {
    bail!("upstream name must not be empty");
  }

  validate_http3_protocol_config(
    upstream.http3.as_ref(),
    &format!("upstream '{}'", upstream.name),
  )?;

  if upstream.addresses.is_empty() {
    if upstream.https.is_some() || upstream.http3.is_some() {
      bail!(
        "direct upstream '{}' must not configure https or http3",
        upstream.name
      );
    }
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

fn validate_address_config(
  upstream_name: &str,
  addr: &UpstreamAddressConfig,
) -> Result<()> {
  addr.protocol()?;
  validate_address_format(&addr.address)?;

  if addr.weight == 0 {
    bail!(
      "upstream '{upstream_name}' address '{}' weight must be greater \
       than 0",
      addr.address
    );
  }

  validate_http3_protocol_config(
    addr.http3.as_ref(),
    &format!("upstream '{upstream_name}' address '{}'", addr.address),
  )?;

  Ok(())
}

fn validate_http3_protocol_config(
  config: Option<&Http3ProtocolConfig>,
  location: &str,
) -> Result<()> {
  if let Some(config) = config {
    validate_duration_positive(
      config.tls_handshake_timeout,
      location,
      "tls_handshake_timeout",
    )?;
    validate_quic_config(config.quic.as_ref(), location)?;
  }
  Ok(())
}

fn validate_quic_config(
  config: Option<&QuicConfig>,
  location: &str,
) -> Result<()> {
  let Some(config) = config else {
    return Ok(());
  };

  validate_duration_positive(
    config.max_idle_timeout,
    location,
    "quic.max_idle_timeout",
  )?;
  validate_duration_positive(
    Some(config.keep_alive_interval),
    location,
    "quic.keep_alive_interval",
  )?;

  if let Some(value) = config.max_concurrent_bidi_streams
    && !(1..=10_000).contains(&value)
  {
    bail!(
      "{location} quic.max_concurrent_bidi_streams must be in \
       1..=10000"
    );
  }

  if let Some(value) = config.initial_mtu
    && !(1200..=9000).contains(&value)
  {
    bail!("{location} quic.initial_mtu must be in 1200..=9000");
  }

  if let Some(value) = config.send_window
    && value == 0
  {
    bail!("{location} quic.send_window must be greater than 0");
  }

  if let Some(value) = config.receive_window
    && value == 0
  {
    bail!("{location} quic.receive_window must be greater than 0");
  }

  Ok(())
}

fn validate_duration_positive(
  value: Option<Duration>,
  location: &str,
  field: &str,
) -> Result<()> {
  if let Some(value) = value
    && value.is_zero()
  {
    bail!("{location} {field} must be greater than 0s");
  }
  Ok(())
}
