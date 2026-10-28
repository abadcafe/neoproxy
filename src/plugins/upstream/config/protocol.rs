//! module: protocol
//! responsibilities: represent upstream protocol and connection pool
//! policy public operations: protocol configuration types
//! data entities: PoolConfig, ProtocolKind tests: raw_tests.rs,
//! resolver_tests.rs through config's public interface
use std::time::Duration;

use serde::Deserialize;

use super::defaults::{
  default_idle_timeout, default_max_idle_per_host,
};

/// Protocol identifier.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProtocolKind {
  Http,
  Https,
  Http3,
  Socks5,
}

impl ProtocolKind {
  pub(crate) fn as_str(&self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Https => "https",
      Self::Http3 => "http3",
      Self::Socks5 => "socks5",
    }
  }
}

/// Resolved idle-cache policy for one process-wide HTTP pool.
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

/// Process-wide pool policy; never inherited by addresses.
#[derive(Clone, Debug)]
pub(crate) struct PoolsConfig {
  pub(crate) http: PoolConfig,
  pub(crate) https: PoolConfig,
  pub(crate) h3_threads: usize,
  pub(crate) h3_connections: usize,
  pub(crate) h3_idle_timeout: Duration,
}
impl Default for PoolsConfig {
  fn default() -> Self {
    Self {
      http: PoolConfig::default(),
      https: PoolConfig::default(),
      h3_threads: 1,
      h3_connections: 2,
      h3_idle_timeout: Duration::from_secs(3600),
    }
  }
}
