//! module: connection_pool
//! responsibility: resolve named connection resource policies
//! public operations: ConnectionPoolConfig, resolve_connection_pools
//! data entities: ConnectionPoolConfig
//! tests: config_tests.rs, validation_tests.rs
use std::collections::HashMap;
use std::time::Duration;

use byte_unit::Byte;
use serde::Deserialize;

use super::protocol::PoolConfig;
use super::raw::{CertificateConfig, UpstreamPluginConfig};
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConnectionPoolConfig {
  pub(crate) name: String,
  #[serde(default)]
  pub(crate) http_max_idle_connections: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) http_connection_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(crate) http3_pool_io_threads: Option<usize>,
  #[serde(default)]
  pub(crate) http3_pool_max_connections_per_host: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) http3_connection_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) dns_refresh_retry_interval: Option<Duration>,
  #[serde(default)]
  pub(crate) dns_servers: Option<Vec<std::net::SocketAddr>>,
  #[serde(default)]
  pub(crate) certificates: Option<CertificateConfig>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) dns_resolve_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) tcp_connect_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) tcp_keep_alive_time: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) tcp_keep_alive_interval: Option<Duration>,
  #[serde(default)]
  pub(crate) tcp_keep_alive_retries: Option<u32>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) tls_handshake_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) quic_connection_connect_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) quic_connection_keep_alive_interval: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) quic_connection_max_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(crate) quic_connection_max_concurrent_bidi_streams: Option<u64>,
  #[serde(default)]
  pub(crate) quic_connection_initial_mtu: Option<u16>,
  #[serde(default)]
  pub(crate) quic_connection_send_window: Option<Byte>,
  #[serde(default)]
  pub(crate) quic_connection_receive_window: Option<Byte>,
  #[serde(default)]
  pub(crate) quic_stream_receive_window: Option<Byte>,
}
impl ConnectionPoolConfig {
  pub(crate) fn dns_timeout(&self) -> Duration {
    self
      .dns_resolve_timeout
      .unwrap_or_else(super::defaults::default_dns_resolve_timeout)
  }

  pub(crate) fn limits(&self) -> super::protocol::PoolsConfig {
    super::protocol::PoolsConfig {
      http: PoolConfig {
        max_idle_per_host: self
          .http_max_idle_connections
          .unwrap_or_else(super::defaults::default_max_idle_per_host),
        idle_timeout: self
          .http_connection_idle_timeout
          .unwrap_or_else(super::defaults::default_idle_timeout),
      },
      https: PoolConfig {
        max_idle_per_host: self
          .http_max_idle_connections
          .unwrap_or_else(super::defaults::default_max_idle_per_host),
        idle_timeout: self
          .http_connection_idle_timeout
          .unwrap_or_else(super::defaults::default_idle_timeout),
      },
      h3_threads: self.http3_pool_io_threads.unwrap_or(1),
      h3_connections: self
        .http3_pool_max_connections_per_host
        .unwrap_or(1),
      h3_idle_timeout: self
        .http3_connection_idle_timeout
        .unwrap_or(Duration::from_secs(60)),
    }
  }
}

pub(crate) fn resolve_connection_pools(
  plugin: &UpstreamPluginConfig,
) -> anyhow::Result<HashMap<String, ConnectionPoolConfig>> {
  let mut pools = HashMap::new();
  for pool in &plugin.connection_pools {
    if pool.name.is_empty() {
      anyhow::bail!("connection pool name must not be empty");
    }
    if pools.insert(pool.name.clone(), pool.clone()).is_some() {
      anyhow::bail!("duplicate connection pool '{}'", pool.name);
    }
  }
  pools.entry("default".into()).or_insert_with(|| {
    ConnectionPoolConfig {
      name: "default".into(),
      ..Default::default()
    }
  });
  Ok(pools)
}
