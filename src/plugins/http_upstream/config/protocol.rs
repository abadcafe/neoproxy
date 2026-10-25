//! module: protocol
//! responsibilities: represent protocol-specific upstream configuration
//! options public operations: protocol configuration types
//! data entities: QuicConfig, HttpProtocolConfig, HttpsProtocolConfig,
//! Http3ProtocolConfig, PoolConfig, ProtocolKind tests: raw_tests.rs,
//! resolver_tests.rs through config's public interface
use std::time::Duration;

use serde::Deserialize;

use super::defaults::{
  default_idle_timeout, default_max_idle_per_host,
};

/// Protocol identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolKind {
  Http,
  Https,
  Http3,
}

/// QUIC transport-layer configuration.
/// Participates in three-level inheritance with field-level merge.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(in crate::plugins::http_upstream::config) struct QuicConfig {
  #[serde(with = "humantime_serde", default)]
  pub(in crate::plugins::http_upstream::config) max_idle_timeout:
    Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(in crate::plugins::http_upstream::config) keep_alive_interval:
    Option<Duration>,
  #[serde(default)]
  pub(in crate::plugins::http_upstream::config) max_concurrent_bidi_streams:
    Option<u64>,
  #[serde(default)]
  pub(in crate::plugins::http_upstream::config) initial_mtu:
    Option<u16>,
  #[serde(default)]
  pub(in crate::plugins::http_upstream::config) send_window:
    Option<u64>,
  #[serde(default)]
  pub(in crate::plugins::http_upstream::config) receive_window:
    Option<u64>,
}

/// HTTP protocol configuration. Participates in three-level
/// inheritance.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(in crate::plugins::http_upstream::config) struct HttpProtocolConfig
{
  #[serde(with = "humantime_serde", default)]
  pub(in crate::plugins::http_upstream::config) connect_timeout:
    Option<Duration>,
}

/// HTTPS protocol configuration. Participates in three-level
/// inheritance.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(in crate::plugins::http_upstream::config) struct HttpsProtocolConfig
{
  #[serde(with = "humantime_serde", default)]
  pub(in crate::plugins::http_upstream::config) connect_timeout:
    Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(in crate::plugins::http_upstream::config) tls_handshake_timeout:
    Option<Duration>,
}

/// HTTP/3 protocol configuration. Participates in three-level
/// inheritance. No `connect_timeout` because QUIC connection timeout is
/// governed by quinn transport config.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(in crate::plugins::http_upstream::config) struct Http3ProtocolConfig
{
  #[serde(with = "humantime_serde", default)]
  pub(in crate::plugins::http_upstream::config) tls_handshake_timeout:
    Option<Duration>,
  #[serde(default)]
  pub(in crate::plugins::http_upstream::config) quic:
    Option<QuicConfig>,
}

/// Connection pool configuration. At upstream level only, NOT
/// inherited.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolConfig {
  #[serde(default = "default_max_idle_per_host")]
  pub(crate) max_idle_per_host: usize,
  #[serde(with = "humantime_serde", default = "default_idle_timeout")]
  pub(crate) idle_timeout: Duration,
}

impl Default for PoolConfig {
  fn default() -> Self {
    Self {
      max_idle_per_host: default_max_idle_per_host(),
      idle_timeout: default_idle_timeout(),
    }
  }
}
