//! module: config::tls
//! responsibility: compile immutable configured TLS identities
//! public operations: CertificateConfig, cert_path, key_path,
//! ServerTlsConfig, compile, client_roots, certificates,
//! client_ca_certs, validate_server_tls
//! data entities: CertificateConfig, ServerTlsConfig
//! tests: tls_tests.rs

//! TLS configuration types and validation.

use std::fs;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use serde::Deserialize;

use super::error::{ConfigError, ConfigErrorCollector};

/// Certificate configuration (cert + key pair)
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateConfig {
  /// Path to certificate file (PEM format)
  pub(in crate::config) cert_path: String,
  /// Path to private key file (PEM format)
  pub(in crate::config) key_path: String,
}

impl CertificateConfig {
  pub(crate) fn cert_path(&self) -> &str {
    &self.cert_path
  }

  pub(crate) fn key_path(&self) -> &str {
    &self.key_path
  }
}

/// Server-level TLS configuration
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerTlsConfig {
  /// List of certificates (cert_path + key_path pairs)
  pub(in crate::config) certificates: Vec<CertificateConfig>,
  /// CA roots contributed to each associated TLS listener's shared
  /// client trust store. A nonempty list requires HTTPS/H3 requests
  /// routed here to present a certificate authenticated by that store.
  /// Omitted and empty lists both leave client authentication
  /// optional.
  #[serde(default)]
  pub(in crate::config) client_ca_certs: Vec<String>,
  #[serde(skip)]
  compiled:
    Arc<OnceLock<Result<Arc<crate::certificate::Candidates>, String>>>,
  #[serde(skip)]
  roots: Arc<OnceLock<Result<rustls::RootCertStore, String>>>,
}

impl std::fmt::Debug for ServerTlsConfig {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ServerTlsConfig")
      .field("certificates", &self.certificates)
      .field("client_ca_certs", &self.client_ca_certs)
      .finish()
  }
}

impl ServerTlsConfig {
  /// Compile a configuration snapshot explicitly. Clones share its
  /// certificate/CA caches; no worker or handshake reads the files
  /// again.
  pub(crate) fn compile(
    &self,
    hostnames: &[String],
  ) -> Result<Arc<crate::certificate::Candidates>> {
    let candidates = self
      .compiled
      .get_or_init(|| {
        crate::certificate::Candidates::load(
          self
            .certificates
            .iter()
            .map(|cert| (cert.cert_path(), cert.key_path())),
        )
        .map(Arc::new)
        .map_err(|error| format!("{error:#}"))
      })
      .as_ref()
      .map_err(|error| anyhow::anyhow!("{error}"))?;
    candidates.validate_names(hostnames)?;
    let _ = self.client_roots()?;
    Ok(candidates.clone())
  }

  pub(crate) fn client_roots(&self) -> Result<&rustls::RootCertStore> {
    self
      .roots
      .get_or_init(|| {
        crate::certificate::load_roots(&self.client_ca_certs)
          .map_err(|error| format!("{error:#}"))
      })
      .as_ref()
      .map_err(|error| anyhow::anyhow!("{error}"))
  }

  pub(crate) fn certificates(&self) -> &[CertificateConfig] {
    &self.certificates
  }

  pub(crate) fn client_ca_certs(&self) -> &[String] {
    &self.client_ca_certs
  }
}

/// Validate server-level TLS configuration.
pub(super) fn validate_server_tls(
  tls: &ServerTlsConfig,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if tls.certificates().is_empty() {
    collector.add(ConfigError::InvalidFormat {
      location: format!("{}.certificates", location),
      message: "at least one certificate is required".into(),
    });
    return;
  }

  for (idx, cert) in tls.certificates().iter().enumerate() {
    let cert_location = format!("{}.certificates[{}]", location, idx);

    match fs::read_to_string(std::path::Path::new(cert.cert_path())) {
      Ok(content) => {
        if !content.contains("-----BEGIN CERTIFICATE-----")
          && !content.contains("-----BEGIN TRUSTED CERTIFICATE-----")
        {
          collector.add(ConfigError::InvalidFormat {
            location: format!("{}.cert_path", cert_location),
            message: format!(
              "certificate file '{}' is not in PEM format",
              cert.cert_path()
            ),
          });
        }
      }
      Err(e) => {
        collector.add(ConfigError::FileRead {
          location: format!("{}.cert_path", cert_location),
          message: format!(
            "certificate file '{}' cannot be read: {}",
            cert.cert_path(),
            e
          ),
        });
      }
    }

    match fs::read_to_string(std::path::Path::new(cert.key_path())) {
      Ok(content) => {
        if !content.contains("-----BEGIN PRIVATE KEY-----")
          && !content.contains("-----BEGIN RSA PRIVATE KEY-----")
          && !content.contains("-----BEGIN EC PRIVATE KEY-----")
          && !content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        {
          collector.add(ConfigError::InvalidFormat {
            location: format!("{}.key_path", cert_location),
            message: format!(
              "private key file '{}' is not in PEM format",
              cert.key_path()
            ),
          });
        }
      }
      Err(e) => {
        collector.add(ConfigError::FileRead {
          location: format!("{}.key_path", cert_location),
          message: format!(
            "private key file '{}' cannot be read: {}",
            cert.key_path(),
            e
          ),
        });
      }
    }
  }
}
