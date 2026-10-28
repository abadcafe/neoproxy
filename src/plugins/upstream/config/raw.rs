//! module: plugins::upstream::config::raw
//! responsibility: deserialize unresolved upstream policy
//! public operations: CertificateConfig, validate,
//! UpstreamAddressConfig, address_protocol, UpstreamConfig,
//! UpstreamPluginConfig, UpstreamServiceArgs
//! data entities: CertificateConfig, UpstreamAddressConfig,
//! UpstreamConfig, UpstreamPluginConfig, UpstreamServiceArgs
//! tests: raw_tests.rs

use std::time::Duration;

use anyhow::{Result, bail};
use serde::Deserialize;

use super::defaults::default_weight;
use super::protocol::ProtocolKind;
use crate::config::UserCredential;

/// TLS identity and trust configuration shared within one connection
/// pool. Does not participate in upstream/address inheritance.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateConfig {
  #[serde(default)]
  pub(crate) client_cert_path: Option<String>,
  #[serde(default)]
  pub(crate) client_key_path: Option<String>,
  #[serde(default)]
  pub(crate) server_ca_path: Option<String>,
}

impl CertificateConfig {
  pub(crate) fn validate(&self) -> Result<()> {
    let has_cert = self.client_cert_path.is_some();
    let has_key = self.client_key_path.is_some();
    if has_cert != has_key {
      bail!(
        "client_cert_path and client_key_path must both be present or \
         both absent"
      );
    }
    Ok(())
  }
}

/// Upstream address configuration. One protocol must be selected.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamAddressConfig {
  #[serde(default)]
  pub(super) use_connection_pool: Option<String>,
  pub(super) address: String,
  #[serde(default)]
  pub(super) hostname: Option<String>,
  #[serde(default = "default_weight")]
  pub(super) weight: usize,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_read_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_send_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(default)]
  pub(super) address_protocol: Option<ProtocolKind>,
  #[serde(default)]
  pub(super) address_max_fails: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(super) address_fail_timeout: Option<Duration>,
}

impl UpstreamAddressConfig {
  pub(crate) fn address_protocol(&self) -> Result<ProtocolKind> {
    Ok(self.address_protocol.clone().unwrap_or(ProtocolKind::Https))
  }
}

/// Upstream configuration.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct UpstreamConfig {
  #[serde(default)]
  pub(super) upstream_non_idempotent_retry: Option<bool>,
  #[serde(default)]
  pub(super) use_connection_pool: Option<String>,
  #[serde(default)]
  pub(super) address_protocol: Option<ProtocolKind>,
  pub(super) name: String,
  #[serde(default)]
  pub(super) addresses: Vec<UpstreamAddressConfig>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_read_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_send_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(default)]
  pub(super) address_max_fails: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(super) address_fail_timeout: Option<Duration>,
}

/// Top-level plugin configuration.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamPluginConfig {
  #[serde(default)]
  pub(super) upstream_non_idempotent_retry: Option<bool>,
  #[serde(default)]
  pub(super) connection_pools:
    Vec<super::connection_pool::ConnectionPoolConfig>,
  #[serde(default)]
  pub(super) use_connection_pool: Option<String>,
  #[serde(default)]
  pub(super) address_protocol: Option<ProtocolKind>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_read_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_send_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(default)]
  pub(super) address_max_fails: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(super) address_fail_timeout: Option<Duration>,

  #[serde(default)]
  pub(super) upstreams: Vec<UpstreamConfig>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamServiceArgs {
  /// Upstream name (required). References an upstream in the plugin
  /// config. An upstream with no addresses = direct mode; with
  /// addresses = chain mode.
  pub(crate) upstream: String,
}
