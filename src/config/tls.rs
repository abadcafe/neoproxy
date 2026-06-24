//! TLS configuration types and validation.

use std::fs;

use serde::Deserialize;

use super::{ConfigError, ConfigErrorCollector};

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
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerTlsConfig {
  /// List of certificates (cert_path + key_path pairs)
  pub(in crate::config) certificates: Vec<CertificateConfig>,
  /// Optional client CA certificates for mTLS
  #[serde(default)]
  pub(in crate::config) client_ca_certs: Option<Vec<String>>,
}

impl ServerTlsConfig {
  pub(crate) fn certificates(&self) -> &[CertificateConfig] {
    &self.certificates
  }

  pub(crate) fn client_ca_certs(&self) -> Option<&[String]> {
    self.client_ca_certs.as_deref()
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
