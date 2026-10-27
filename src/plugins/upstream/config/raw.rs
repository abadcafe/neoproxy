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
use super::protocol::{PoolConfig, ProtocolKind};
use crate::config::UserCredential;

/// Global TLS client identity configuration. Shared across all
/// upstreams. Does NOT participate in three-level inheritance.
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
  pub(super) address: String,
  #[serde(default)]
  pub(super) hostname: Option<String>,
  #[serde(default = "default_weight")]
  pub(super) weight: usize,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_request_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(default)]
  pub(super) address_protocol: Option<ProtocolKind>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_connect_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) address_max_fails: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(super) address_fail_timeout: Option<Duration>,

  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_keep_alive_time: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_keep_alive_interval: Option<Duration>,
  #[serde(default)]
  pub(super) tcp_keep_alive_retries: Option<u32>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tls_handshake_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_connect_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_keep_alive_interval: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) quic_connection_max_concurrent_bidi_streams: Option<u64>,
  #[serde(default)]
  pub(super) quic_connection_initial_mtu: Option<u16>,
  #[serde(default)]
  pub(super) quic_connection_send_window: Option<u64>,
  #[serde(default)]
  pub(super) quic_connection_receive_window: Option<u64>,
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
  pub(super) address_protocol: Option<ProtocolKind>,
  pub(super) name: String,
  #[serde(default)]
  pub(super) addresses: Vec<UpstreamAddressConfig>,
  #[serde(default)]
  pub(super) pool: Option<PoolConfig>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_request_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_connect_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) address_max_fails: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(super) address_fail_timeout: Option<Duration>,

  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_keep_alive_time: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_keep_alive_interval: Option<Duration>,
  #[serde(default)]
  pub(super) tcp_keep_alive_retries: Option<u32>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tls_handshake_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_connect_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_keep_alive_interval: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) quic_connection_max_concurrent_bidi_streams: Option<u64>,
  #[serde(default)]
  pub(super) quic_connection_initial_mtu: Option<u16>,
  #[serde(default)]
  pub(super) quic_connection_send_window: Option<u64>,
  #[serde(default)]
  pub(super) quic_connection_receive_window: Option<u64>,
}

/// Top-level plugin configuration.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamPluginConfig {
  #[serde(default)]
  pub(super) address_protocol: Option<ProtocolKind>,
  #[serde(with = "humantime_serde", default)]
  pub(super) dns_refresh_retry_interval: Option<Duration>,
  #[serde(default)]
  pub(super) dns_servers: Option<Vec<std::net::SocketAddr>>,
  #[serde(default)]
  pub(crate) certificates: Option<CertificateConfig>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) dns_resolve_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) upstream_request_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_connect_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) address_max_fails: Option<usize>,
  #[serde(with = "humantime_serde", default)]
  pub(super) address_fail_timeout: Option<Duration>,

  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_keep_alive_time: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tcp_keep_alive_interval: Option<Duration>,
  #[serde(default)]
  pub(super) tcp_keep_alive_retries: Option<u32>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tls_handshake_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_connect_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_keep_alive_interval: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) quic_connection_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) quic_connection_max_concurrent_bidi_streams: Option<u64>,
  #[serde(default)]
  pub(super) quic_connection_initial_mtu: Option<u16>,
  #[serde(default)]
  pub(super) quic_connection_send_window: Option<u64>,
  #[serde(default)]
  pub(super) quic_connection_receive_window: Option<u64>,
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
