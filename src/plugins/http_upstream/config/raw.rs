use std::time::Duration;

use anyhow::{Result, bail};
use serde::Deserialize;

use super::defaults::{
  default_idle_timeout, default_keep_alive_interval,
  default_max_idle_per_host, default_weight,
};
use super::resolved::ProtocolKind;
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

/// QUIC transport-layer configuration.
/// Participates in three-level inheritance with field-level merge.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct QuicConfig {
  #[serde(with = "humantime_serde", default)]
  pub(super) max_idle_timeout: Option<Duration>,
  #[serde(
    with = "humantime_serde",
    default = "default_keep_alive_interval"
  )]
  pub(super) keep_alive_interval: Duration,
  #[serde(default)]
  pub(super) max_concurrent_bidi_streams: Option<u64>,
  #[serde(default)]
  pub(super) initial_mtu: Option<u16>,
  #[serde(default)]
  pub(super) send_window: Option<u64>,
  #[serde(default)]
  pub(super) receive_window: Option<u64>,
}

/// HTTP protocol configuration. Participates in three-level
/// inheritance.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpProtocolConfig {
  #[serde(with = "humantime_serde", default)]
  pub(super) connect_timeout: Option<Duration>,
}

/// HTTPS protocol configuration. Participates in three-level
/// inheritance.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpsProtocolConfig {
  #[serde(with = "humantime_serde", default)]
  pub(super) connect_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tls_handshake_timeout: Option<Duration>,
}

/// HTTP/3 protocol configuration. Participates in three-level
/// inheritance. No `connect_timeout` because QUIC connection timeout is
/// governed by quinn transport config.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Http3ProtocolConfig {
  #[serde(with = "humantime_serde", default)]
  pub(super) tls_handshake_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) quic: Option<QuicConfig>,
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

/// Upstream address configuration. Exactly one protocol block must be
/// set.
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
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(default)]
  pub(super) http: Option<HttpProtocolConfig>,
  #[serde(default)]
  pub(super) https: Option<HttpsProtocolConfig>,
  #[serde(default)]
  pub(super) http3: Option<Http3ProtocolConfig>,
}

impl UpstreamAddressConfig {
  pub(crate) fn protocol(&self) -> Result<ProtocolKind> {
    let count =
      [self.http.is_some(), self.https.is_some(), self.http3.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();
    match count {
      0 => bail!(
        "address '{}' must specify exactly one protocol block (http, \
         https, or http3)",
        self.address
      ),
      1 => {
        if self.http.is_some() {
          Ok(ProtocolKind::Http)
        } else if self.https.is_some() {
          Ok(ProtocolKind::Https)
        } else {
          Ok(ProtocolKind::Http3)
        }
      }
      _ => bail!(
        "address '{}' must have exactly one protocol block, found {}",
        self.address,
        count
      ),
    }
  }
}

/// Upstream configuration.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(super) struct UpstreamConfig {
  pub(super) name: String,
  #[serde(default)]
  pub(super) addresses: Vec<UpstreamAddressConfig>,
  #[serde(default)]
  pub(super) pool: Option<PoolConfig>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) dns_resolve_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(default)]
  pub(super) http: Option<HttpProtocolConfig>,
  #[serde(default)]
  pub(super) https: Option<HttpsProtocolConfig>,
  #[serde(default)]
  pub(super) http3: Option<Http3ProtocolConfig>,
}

/// Top-level plugin configuration.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpUpstreamPluginConfig {
  #[serde(default)]
  pub(crate) certificates: Option<CertificateConfig>,
  #[serde(with = "humantime_serde", default)]
  pub(super) tunnel_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(super) dns_resolve_timeout: Option<Duration>,
  #[serde(default)]
  pub(super) user: Option<UserCredential>,
  #[serde(default)]
  pub(super) http: Option<HttpProtocolConfig>,
  #[serde(default)]
  pub(super) https: Option<HttpsProtocolConfig>,
  #[serde(default)]
  pub(super) http3: Option<Http3ProtocolConfig>,
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
