use std::collections::HashMap;
use std::path;
use std::time::Duration;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;

use crate::config::UserCredential;
use super::default_idle_timeout;

// ============================================================================
// Client TLS Configuration
// ============================================================================

/// Client TLS configuration for http3_chain.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientTlsConfig {
  #[serde(default)]
  pub(crate) client_cert_path: Option<String>,
  #[serde(default)]
  pub(crate) client_key_path: Option<String>,
  #[serde(default)]
  pub(crate) server_ca_path: Option<String>,
}

impl ClientTlsConfig {
  pub(crate) fn validate_if_non_empty(&self) -> Result<()> {
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

  /// Deep merge with a default TLS config.
  /// Fields in `self` take priority; missing fields are inherited from
  /// `default`.
  pub(crate) fn deep_merge(&self, default: &ClientTlsConfig) -> ClientTlsConfig {
    ClientTlsConfig {
      client_cert_path: self
        .client_cert_path
        .clone()
        .or_else(|| default.client_cert_path.clone()),
      client_key_path: self
        .client_key_path
        .clone()
        .or_else(|| default.client_key_path.clone()),
      server_ca_path: self
        .server_ca_path
        .clone()
        .or_else(|| default.server_ca_path.clone()),
    }
  }
}

// ============================================================================
// Credential Types
// ============================================================================

/// User password credential for proxy authentication.
#[derive(Clone, Debug)]
pub(crate) struct UserPasswordCredential {
  pub(crate) user: Option<UserCredential>,
}

impl UserPasswordCredential {
  pub(crate) fn none() -> Self {
    Self { user: None }
  }

  pub(crate) fn apply(&self, req: &mut http::Request<()>) {
    if let Some(ref user) = self.user {
      let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", user.username, user.password));
      req.headers_mut().insert(
        "Proxy-Authorization",
        http::HeaderValue::from_str(&format!("Basic {}", credentials))
          .unwrap(),
      );
    }
  }
}

/// Client certificate credential for TLS authentication.
#[derive(Clone, Debug)]
pub(crate) struct ClientCertCredential {
  pub(crate) cert_path: Option<path::PathBuf>,
  pub(crate) key_path: Option<path::PathBuf>,
}

impl ClientCertCredential {
  pub(crate) fn none() -> Self {
    Self { cert_path: None, key_path: None }
  }

  pub(crate) fn build_tls_config(
    &self,
    roots: rustls::RootCertStore,
  ) -> Result<rustls::ClientConfig> {
    match (&self.cert_path, &self.key_path) {
      (Some(cert_path), Some(key_path)) => {
        let cert_file = fs::File::open(cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let cert_chain: Vec<CertificateDer> =
          rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()?;
        let key_file = fs::File::open(key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
          .ok_or_else(|| anyhow!("no private key found"))?;
        Ok(
          rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, key)?,
        )
      }
      (None, None) => Ok(
        rustls::ClientConfig::builder()
          .with_root_certificates(roots)
          .with_no_client_auth(),
      ),
      _ => bail!(
        "client_cert_path and client_key_path must both be present or \
         both absent"
      ),
    }
  }
}

// ============================================================================
// Plugin-level Configuration — Three-level Inheritance
// ============================================================================

/// QUIC transport-layer configuration.
/// Items here are passed directly to `quinn::TransportConfig`.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuicConfig {
  /// Interval for sending PING frames to keep the QUIC connection alive.
  /// Default: 3s
  #[serde(with = "humantime_serde", default = "default_keep_alive_interval")]
  pub(crate) keep_alive_interval: Duration,
  /// QUIC connection-level idle timeout.
  /// When set, overrides the peer-negotiated default.
  #[serde(with = "humantime_serde", default)]
  pub(crate) max_idle_timeout: Option<Duration>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Http3ChainPluginConfig {
  #[serde(default)]
  pub(crate) upstreams: Vec<UpstreamConfig>,
  /// Tunnel idle timeout (not QUIC-level)
  #[serde(with = "humantime_serde", default)]
  pub(crate) max_idle_timeout: Option<Duration>,
  /// QUIC transport parameters
  #[serde(default)]
  pub(crate) quic: Option<QuicConfig>,
  #[serde(default)]
  pub(crate) user: Option<UserCredential>,
  #[serde(default)]
  pub(crate) tls: Option<ClientTlsConfig>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamConfig {
  pub(crate) name: String,
  #[serde(default)]
  pub(crate) addresses: Vec<UpstreamAddressConfig>,
  /// Tunnel idle timeout (not QUIC-level)
  #[serde(with = "humantime_serde", default)]
  pub(crate) max_idle_timeout: Option<Duration>,
  /// QUIC transport parameters (overrides plugin-level)
  #[serde(default)]
  pub(crate) quic: Option<QuicConfig>,
  #[serde(default)]
  pub(crate) user: Option<UserCredential>,
  #[serde(default)]
  pub(crate) tls: Option<ClientTlsConfig>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamAddressConfig {
  pub(crate) address: String,
  #[serde(default)]
  pub(crate) hostname: Option<String>,
  #[serde(default = "default_weight")]
  pub(crate) weight: usize,
  /// Tunnel idle timeout (not QUIC-level)
  #[serde(with = "humantime_serde", default)]
  pub(crate) max_idle_timeout: Option<Duration>,
  /// QUIC transport parameters (overrides upstream-level)
  #[serde(default)]
  pub(crate) quic: Option<QuicConfig>,
  #[serde(default)]
  pub(crate) user: Option<UserCredential>,
  #[serde(default)]
  pub(crate) tls: Option<ClientTlsConfig>,
}

fn default_weight() -> usize { 1 }
fn default_keep_alive_interval() -> Duration { Duration::from_secs(3) }

// ============================================================================
// Resolved Configuration Types
// ============================================================================

/// Resolved QUIC-layer config from three-level inheritance.
#[derive(Clone, Debug)]
pub(crate) struct QuicResolved {
  pub(crate) keep_alive_interval: Duration,
  pub(crate) max_idle_timeout: Option<Duration>,
}

/// Resolved config for a single upstream address after three-level
/// inheritance (Plugin -> Upstream -> Address).
#[derive(Clone, Debug)]
pub(crate) struct ResolvedAddress {
  pub(crate) address: String,
  pub(crate) hostname: Option<String>,
  pub(crate) weight: usize,
  pub(crate) current_weight: isize,
  pub(crate) max_idle_timeout: Duration,
  pub(crate) quic: QuicResolved,
  pub(crate) user_password_credential: UserPasswordCredential,
  pub(crate) client_cert_credential: ClientCertCredential,
  pub(crate) server_ca_path: Option<String>,
}

/// Resolved config for an upstream, containing all its addresses.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedUpstream {
  pub(crate) addresses: Vec<ResolvedAddress>,
}

// ============================================================================
// Service Configuration
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Http3ChainServiceArgs {
  pub(crate) upstream: String,
}

impl Http3ChainServiceArgs {
  pub(crate) fn validate(&self) -> Result<()> {
    if self.upstream.is_empty() {
      bail!("upstream name cannot be empty");
    }
    Ok(())
  }
}

// ============================================================================
// Three-level Inheritance
// ============================================================================

pub(crate) fn deep_merge_tls(
  addr_tls: &Option<ClientTlsConfig>,
  upstream_tls: &Option<ClientTlsConfig>,
  plugin_tls: &Option<ClientTlsConfig>,
) -> Option<ClientTlsConfig> {
  // Three-level merge: address > upstream > plugin
  let step1 = match (upstream_tls, plugin_tls) {
    (Some(u), Some(p)) => Some(u.deep_merge(p)),
    (Some(u), None) => Some(u.clone()),
    (None, Some(p)) => Some(p.clone()),
    (None, None) => None,
  };
  match (addr_tls, &step1) {
    (Some(a), Some(s)) => Some(a.deep_merge(s)),
    (Some(a), None) => Some(a.clone()),
    (None, Some(s)) => Some(s.clone()),
    (None, None) => None,
  }
}

pub(crate) fn resolve_three_level(
  plugin: &Http3ChainPluginConfig,
) -> Result<HashMap<String, ResolvedUpstream>> {
  let mut upstreams: HashMap<String, ResolvedUpstream> = HashMap::new();

  for upstream in &plugin.upstreams {
    let mut addresses = Vec::new();

    for addr in &upstream.addresses {
      // Resolve TLS: address > upstream > plugin
      let effective_tls = deep_merge_tls(
        &addr.tls, &upstream.tls, &plugin.tls,
      );
      if let Some(ref tls) = effective_tls {
        tls.validate_if_non_empty()
          .with_context(|| format!(
            "upstream '{}' address '{}' tls", upstream.name, addr.address))?;
      }

      // Resolve user: address > upstream > plugin
      let effective_user = addr.user.clone()
        .or_else(|| upstream.user.clone())
        .or_else(|| plugin.user.clone());

      let upc = match effective_user {
        Some(user) => UserPasswordCredential { user: Some(user) },
        None => UserPasswordCredential::none(),
      };

      let (ccc, server_ca_path) = match &effective_tls {
        None => (ClientCertCredential::none(), None),
        Some(tls_config) => {
          let ccc = match (&tls_config.client_cert_path, &tls_config.client_key_path) {
            (Some(cert), Some(key)) => ClientCertCredential {
              cert_path: Some(cert.into()),
              key_path: Some(key.into()),
            },
            _ => ClientCertCredential::none(),
          };
          (ccc, tls_config.server_ca_path.clone())
        }
      };

      // Resolve max_idle_timeout (tunnel layer): address > upstream > plugin > default
      let max_idle_timeout = addr.max_idle_timeout
        .or(upstream.max_idle_timeout)
        .or(plugin.max_idle_timeout)
        .unwrap_or_else(default_idle_timeout);

      // Resolve quic layer: address.quic > upstream.quic > plugin.quic
      let quic = {
        let q = addr.quic.as_ref()
          .or(upstream.quic.as_ref())
          .or(plugin.quic.as_ref());
        QuicResolved {
          keep_alive_interval: q.map(|c| c.keep_alive_interval)
            .unwrap_or_else(default_keep_alive_interval),
          max_idle_timeout: q.and_then(|c| c.max_idle_timeout),
        }
      };

      // Validate address format
      validate_address_format(&addr.address)?;

      addresses.push(ResolvedAddress {
        address: addr.address.clone(),
        hostname: addr.hostname.clone(),
        weight: addr.weight,
        current_weight: 0,
        max_idle_timeout,
        quic,
        user_password_credential: upc,
        client_cert_credential: ccc,
        server_ca_path,
      });
    }

    upstreams.insert(upstream.name.clone(), ResolvedUpstream {
      addresses,
    });
  }

  Ok(upstreams)
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validate that an address string has host:port format without DNS resolution.
pub(crate) fn validate_address_format(s: &str) -> Result<()> {
  let colon_pos = s
    .rfind(':')
    .ok_or_else(|| anyhow!("address '{s}' missing port"))?;
  let port_str = &s[colon_pos + 1..];
  port_str
    .parse::<u16>()
    .with_context(|| format!("address '{s}' has invalid port"))?;
  let host = &s[..colon_pos];
  if host.is_empty() {
    anyhow::bail!("address '{s}' missing host");
  }
  Ok(())
}