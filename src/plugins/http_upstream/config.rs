use std::collections::HashMap;
use std::path;
use std::time::Duration;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;

use crate::config::UserCredential;
use super::inherit::{resolve_field, resolve_field_with_default};

// ============================================================================
// Defaults
// ============================================================================

fn default_weight() -> usize { 1 }
fn default_connect_timeout() -> Duration { Duration::from_secs(10) }
fn default_tunnel_idle_timeout() -> Duration { Duration::from_secs(60) }
fn default_tls_handshake_timeout() -> Duration { Duration::from_secs(10) }
fn default_keep_alive_interval() -> Duration { Duration::from_secs(3) }
fn default_max_idle_per_host() -> usize { 32 }
fn default_idle_timeout() -> Duration { Duration::from_secs(90) }

// ============================================================================
// Credential Types
// ============================================================================

/// User password credential for proxy authentication.
#[derive(Clone, Debug)]
pub(crate) struct UserPasswordCredential {
  pub(crate) user: Option<UserCredential>,
}

impl UserPasswordCredential {
  pub(crate) fn none() -> Self { Self { user: None } }

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
// Serde Config Structs (all deny_unknown_fields)
// ============================================================================

/// Global TLS client identity configuration. Shared across all upstreams.
/// Does NOT participate in three-level inheritance.
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
pub(crate) struct QuicConfig {
  #[serde(with = "humantime_serde", default)]
  pub(crate) max_idle_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default = "default_keep_alive_interval")]
  pub(crate) keep_alive_interval: Duration,
  #[serde(default)]
  pub(crate) max_concurrent_bidi_streams: Option<u64>,
  #[serde(default)]
  pub(crate) initial_mtu: Option<u16>,
  #[serde(default)]
  pub(crate) send_window: Option<u64>,
  #[serde(default)]
  pub(crate) receive_window: Option<u64>,
}

/// HTTP protocol configuration. Participates in three-level inheritance.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpProtocolConfig {
  #[serde(with = "humantime_serde", default)]
  pub(crate) connect_timeout: Option<Duration>,
}

/// HTTPS protocol configuration. Participates in three-level inheritance.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpsProtocolConfig {
  #[serde(with = "humantime_serde", default)]
  pub(crate) connect_timeout: Option<Duration>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) tls_handshake_timeout: Option<Duration>,
}

/// HTTP/3 protocol configuration. Participates in three-level inheritance.
/// No `connect_timeout` — QUIC connection timeout governed by quinn transport config.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct Http3ProtocolConfig {
  #[serde(with = "humantime_serde", default)]
  pub(crate) tls_handshake_timeout: Option<Duration>,
  #[serde(default)]
  pub(crate) quic: Option<QuicConfig>,
}

/// Connection pool configuration. At upstream level only, NOT inherited.
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

/// Upstream address configuration. Exactly one protocol block must be set.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamAddressConfig {
  pub(crate) address: String,
  #[serde(default)]
  pub(crate) hostname: Option<String>,
  #[serde(default = "default_weight")]
  pub(crate) weight: usize,
  #[serde(with = "humantime_serde", default)]
  pub(crate) tunnel_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(crate) user: Option<UserCredential>,
  #[serde(default)]
  pub(crate) http: Option<HttpProtocolConfig>,
  #[serde(default)]
  pub(crate) https: Option<HttpsProtocolConfig>,
  #[serde(default)]
  pub(crate) http3: Option<Http3ProtocolConfig>,
}

impl UpstreamAddressConfig {
  pub(crate) fn protocol(&self) -> Result<ProtocolKind> {
    let count = [self.http.is_some(), self.https.is_some(), self.http3.is_some()]
      .iter()
      .filter(|&&x| x)
      .count();
    match count {
      0 => bail!(
        "address '{}' must specify exactly one protocol block (http, https, or http3)",
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
        self.address, count
      ),
    }
  }
}

/// Upstream configuration.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamConfig {
  pub(crate) name: String,
  #[serde(default)]
  pub(crate) addresses: Vec<UpstreamAddressConfig>,
  #[serde(default)]
  pub(crate) pool: Option<PoolConfig>,
  #[serde(with = "humantime_serde", default)]
  pub(crate) tunnel_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(crate) user: Option<UserCredential>,
  #[serde(default)]
  pub(crate) http: Option<HttpProtocolConfig>,
  #[serde(default)]
  pub(crate) https: Option<HttpsProtocolConfig>,
  #[serde(default)]
  pub(crate) http3: Option<Http3ProtocolConfig>,
}

/// Plugin-level upstream defaults (protocol-scoped).
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamDefaultsConfig {
  #[serde(with = "humantime_serde", default)]
  pub(crate) tunnel_idle_timeout: Option<Duration>,
  #[serde(default)]
  pub(crate) user: Option<UserCredential>,
  #[serde(default)]
  pub(crate) http: Option<HttpProtocolConfig>,
  #[serde(default)]
  pub(crate) https: Option<HttpsProtocolConfig>,
  #[serde(default)]
  pub(crate) http3: Option<Http3ProtocolConfig>,
}

/// Top-level plugin configuration.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpUpstreamPluginConfig {
  #[serde(default)]
  pub(crate) certificates: Option<CertificateConfig>,
  #[serde(default)]
  pub(crate) upstream: UpstreamDefaultsConfig,
  #[serde(default)]
  pub(crate) upstreams: Vec<UpstreamConfig>,
}

// ============================================================================
// Service Args
// ============================================================================

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamServiceArgs {
  /// Upstream name (required). References an upstream in the plugin config.
  /// An upstream with no addresses = direct mode; with addresses = chain mode.
  pub(crate) upstream: String,
}

// ============================================================================
// Resolved Types
// ============================================================================

/// Protocol identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolKind {
  Http,
  Https,
  Http3,
}

/// Resolved QUIC config from field-level three-level merge.
#[derive(Clone, Debug)]
pub(crate) struct QuicResolved {
  pub(crate) max_idle_timeout: Option<Duration>,
  pub(crate) keep_alive_interval: Duration,
  pub(crate) max_concurrent_bidi_streams: Option<u64>,
  pub(crate) initial_mtu: Option<u16>,
  pub(crate) send_window: Option<u64>,
  pub(crate) receive_window: Option<u64>,
}

/// Resolved protocol with all fields filled.
#[derive(Clone, Debug)]
pub(crate) enum Protocol {
  Http {
    connect_timeout: Duration,
  },
  Https {
    connect_timeout: Duration,
    tls_handshake_timeout: Duration,
  },
  Http3 {
    tls_handshake_timeout: Duration,
    quic: QuicResolved,
  },
}

/// Resolved address after three-level inheritance.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedAddress {
  pub(crate) address: String,
  pub(crate) hostname: Option<String>,
  pub(crate) weight: usize,
  pub(crate) current_weight: std::cell::Cell<isize>,
  pub(crate) protocol: Protocol,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) user: UserPasswordCredential,
}

/// Resolved upstream after three-level inheritance.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedUpstream {
  pub(crate) addresses: Vec<ResolvedAddress>,
  pub(crate) pool_config: PoolConfig,
  /// Direct-mode fields (used when addresses is empty):
  pub(crate) connect_timeout: Duration,
  pub(crate) tunnel_idle_timeout: Duration,
}

// ============================================================================
// Three-level Inheritance Resolution
// ============================================================================

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
pub(crate) fn resolve_chain_config(
  plugin: &HttpUpstreamPluginConfig,
) -> Result<HashMap<String, ResolvedUpstream>> {
  let mut upstreams: HashMap<String, ResolvedUpstream> = HashMap::new();

  for upstream in &plugin.upstreams {
    let mut addresses = Vec::new();

    for addr in &upstream.addresses {
      let proto = addr.protocol()?;

      // Protocol-agnostic fields: address → upstream → plugin → default
      let tunnel_idle_timeout = resolve_field_with_default(
        addr.tunnel_idle_timeout.as_ref(),
        upstream.tunnel_idle_timeout.as_ref(),
        plugin.upstream.tunnel_idle_timeout.as_ref(),
        default_tunnel_idle_timeout(),
      );
      let user = resolve_user(
        addr.user.as_ref(),
        upstream.user.as_ref(),
        plugin.upstream.user.as_ref(),
      );

      // Protocol-specific fields: protocol block three-level inheritance
      let resolved_protocol = match proto {
        ProtocolKind::Http => {
          let a = addr.http.as_ref();
          let u = upstream.http.as_ref();
          let p = plugin.upstream.http.as_ref();
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
          let p = plugin.upstream.https.as_ref();
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
          let p = plugin.upstream.http3.as_ref();
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

      addresses.push(ResolvedAddress {
        address: addr.address.clone(),
        hostname: addr.hostname.clone(),
        weight: addr.weight,
        current_weight: std::cell::Cell::new(0),
        protocol: resolved_protocol,
        tunnel_idle_timeout,
        user,
      });
    }

    let pool_config = upstream.pool.clone().unwrap_or_default();

    // Direct-mode fields: resolve from two-level inheritance
    let u_http = upstream.http.as_ref();
    let p_http = plugin.upstream.http.as_ref();
    let connect_timeout = resolve_field_with_default(
      u_http.and_then(|c| c.connect_timeout).as_ref(),
      p_http.and_then(|c| c.connect_timeout).as_ref(),
      None,
      default_connect_timeout(),
    );
    let tunnel_idle_timeout = resolve_field_with_default(
      upstream.tunnel_idle_timeout.as_ref(),
      plugin.upstream.tunnel_idle_timeout.as_ref(),
      None,
      default_tunnel_idle_timeout(),
    );

    upstreams.insert(upstream.name.clone(), ResolvedUpstream {
      addresses,
      pool_config,
      connect_timeout,
      tunnel_idle_timeout,
    });
  }

  Ok(upstreams)
}

/// Resolve user credential through three-level inheritance.
fn resolve_user(
  addr: Option<&UserCredential>,
  upstream: Option<&UserCredential>,
  plugin: Option<&UserCredential>,
) -> UserPasswordCredential {
  match resolve_field(addr, upstream, plugin) {
    Some(user) => UserPasswordCredential { user: Some(user.clone()) },
    None => UserPasswordCredential::none(),
  }
}

// ============================================================================
// Validation & Helpers
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
    bail!("address '{s}' missing host");
  }
  Ok(())
}

/// Build a root certificate store from native certs + optional server CA.
pub(crate) fn build_root_cert_store(
  server_ca_path: Option<&str>,
) -> Result<rustls::RootCertStore> {
  let mut roots = rustls::RootCertStore::empty();
  let rustls_native_certs::CertificateResult { certs, errors, .. } =
    rustls_native_certs::load_native_certs();
  for cert in certs {
    if let Err(e) = roots.add(cert) {
      tracing::error!("failed to parse trust anchor: {e}");
    }
  }
  for e in errors {
    tracing::error!("couldn't load default trust roots: {e}");
  }
  if let Some(path) = server_ca_path {
    let file = fs::File::open(path)
      .with_context(|| format!("opening server CA file: {path}"))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<CertificateDer> =
      rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    for cert in certs {
      roots.add(cert)?;
    }
  }
  Ok(roots)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_validate_address_format_valid() {
    assert!(validate_address_format("example.com:8080").is_ok());
    assert!(validate_address_format("127.0.0.1:443").is_ok());
  }

  #[test]
  fn test_validate_address_format_missing_port() {
    assert!(validate_address_format("example.com").is_err());
  }

  #[test]
  fn test_validate_address_format_invalid_port() {
    assert!(validate_address_format("example.com:abc").is_err());
  }

  #[test]
  fn test_validate_address_format_missing_host() {
    assert!(validate_address_format(":8080").is_err());
  }

  #[test]
  fn test_address_protocol_detection() {
    let addr: UpstreamAddressConfig = serde_yaml::from_str(
      "address: example.com:443\nhttp3: {}",
    ).unwrap();
    assert_eq!(addr.protocol().unwrap(), ProtocolKind::Http3);
  }

  #[test]
  fn test_address_no_protocol_is_error() {
    let addr: UpstreamAddressConfig = serde_yaml::from_str(
      "address: example.com:443",
    ).unwrap();
    assert!(addr.protocol().is_err());
  }

  #[test]
  fn test_address_multiple_protocols_is_error() {
    let addr: UpstreamAddressConfig = serde_yaml::from_str(
      "address: example.com:443\nhttp: {}\nhttps: {}",
    ).unwrap();
    assert!(addr.protocol().is_err());
  }

  #[test]
  fn test_resolve_chain_config_basic() {
    let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
      r#"
      upstreams:
        - name: test
          addresses:
            - address: proxy.example.com:443
              tunnel_idle_timeout: 120s
              http3: {}
      "#,
    ).unwrap();
    let resolved = resolve_chain_config(&config).unwrap();
    let upstream = resolved.get("test").unwrap();
    assert_eq!(upstream.addresses.len(), 1);
    assert_eq!(upstream.addresses[0].address, "proxy.example.com:443");
    assert!(matches!(upstream.addresses[0].protocol, Protocol::Http3 { .. }));
    assert_eq!(upstream.addresses[0].tunnel_idle_timeout, Duration::from_secs(120));
  }

  #[test]
  fn test_resolve_chain_config_pool_config() {
    let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
      r#"
      upstreams:
        - name: test
          pool:
            max_idle_per_host: 16
            idle_timeout: 30s
          addresses:
            - address: proxy.example.com:8080
              http: {}
      "#,
    ).unwrap();
    let resolved = resolve_chain_config(&config).unwrap();
    let upstream = resolved.get("test").unwrap();
    assert_eq!(upstream.pool_config.max_idle_per_host, 16);
  }

  #[test]
  fn test_resolve_chain_config_three_level_inheritance() {
    let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
      r#"
      upstream:
        tunnel_idle_timeout: 90s
        http:
          connect_timeout: 5s
      upstreams:
        - name: test
          http:
            connect_timeout: 3s
          addresses:
            - address: proxy.example.com:8080
              http:
                connect_timeout: 1s
            - address: proxy2.example.com:8080
              http: {}
      "#,
    ).unwrap();
    let resolved = resolve_chain_config(&config).unwrap();
    let upstream = resolved.get("test").unwrap();

    // Address-level overrides upstream-level overrides plugin-level
    match &upstream.addresses[0].protocol {
      Protocol::Http { connect_timeout, .. } => {
        assert_eq!(*connect_timeout, Duration::from_secs(1));
      }
      _ => panic!("expected Http protocol"),
    }
    assert_eq!(upstream.addresses[0].tunnel_idle_timeout, Duration::from_secs(90));

    // Falls back to upstream-level connect_timeout, plugin-level tunnel_idle_timeout
    match &upstream.addresses[1].protocol {
      Protocol::Http { connect_timeout, .. } => {
        assert_eq!(*connect_timeout, Duration::from_secs(3));
      }
      _ => panic!("expected Http protocol"),
    }
    assert_eq!(upstream.addresses[1].tunnel_idle_timeout, Duration::from_secs(90));
  }

  #[test]
  fn test_upstream_service_args_requires_upstream() {
    let result = serde_yaml::from_str::<UpstreamServiceArgs>("{}");
    assert!(result.is_err(), "upstream field should be required");
  }

  #[test]
  fn test_upstream_service_args_with_upstream() {
    let args: UpstreamServiceArgs = serde_yaml::from_str(
      "upstream: test_upstream",
    ).unwrap();
    assert_eq!(args.upstream, "test_upstream");
  }

  #[test]
  fn test_upstream_service_args_deny_unknown_fields() {
    let result = serde_yaml::from_str::<UpstreamServiceArgs>(
      "upstream: test\nconnect_timeout: 5s",
    );
    assert!(result.is_err(), "connect_timeout should be rejected in service args");
  }

  #[test]
  fn test_resolve_direct_upstream() {
    let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
      r#"
      upstreams:
        - name: direct
          http:
            connect_timeout: 3s
          tunnel_idle_timeout: 45s
      "#,
    ).unwrap();
    let resolved = resolve_chain_config(&config).unwrap();
    let upstream = resolved.get("direct").unwrap();
    assert!(upstream.addresses.is_empty());
    assert_eq!(upstream.connect_timeout, Duration::from_secs(3));
    assert_eq!(upstream.tunnel_idle_timeout, Duration::from_secs(45));
  }

  #[test]
  fn test_resolve_direct_upstream_inherits_plugin_defaults() {
    let config: HttpUpstreamPluginConfig = serde_yaml::from_str(
      r#"
      upstream:
        http:
          connect_timeout: 7s
      upstreams:
        - name: direct
      "#,
    ).unwrap();
    let resolved = resolve_chain_config(&config).unwrap();
    let upstream = resolved.get("direct").unwrap();
    assert!(upstream.addresses.is_empty());
    assert_eq!(upstream.connect_timeout, Duration::from_secs(7));
    assert_eq!(upstream.tunnel_idle_timeout, Duration::from_secs(60));
  }

  #[test]
  fn test_plugin_config_deny_unknown_fields() {
    let result = serde_yaml::from_str::<HttpUpstreamPluginConfig>(
      "direct:\n  connect_timeout: 10s\n",
    );
    assert!(result.is_err(), "old 'direct:' field should be rejected");
  }

  #[test]
  fn test_pool_config_defaults() {
    let config = PoolConfig::default();
    assert_eq!(config.max_idle_per_host, 32);
    assert_eq!(config.idle_timeout, Duration::from_secs(90));
  }
}
