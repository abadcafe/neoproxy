//! TLS configuration types and validation.

use std::fs;

use serde::Deserialize;

use super::{ConfigError, ConfigErrorCollector};

/// Certificate configuration (cert + key pair)
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CertificateConfig {
  /// Path to certificate file (PEM format)
  pub cert_path: String,
  /// Path to private key file (PEM format)
  pub key_path: String,
}

/// Server-level TLS configuration
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsConfig {
  /// List of certificates (cert_path + key_path pairs)
  pub certificates: Vec<CertificateConfig>,
  /// Optional client CA certificates for mTLS
  #[serde(default)]
  pub client_ca_certs: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_certificate_config_deserialize() {
    let yaml = r#"
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
"#;
    let cert: CertificateConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cert.cert_path, "/path/to/cert.pem");
    assert_eq!(cert.key_path, "/path/to/key.pem");
  }

  #[test]
  fn test_server_tls_config_deserialize_single_cert() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 1);
    assert_eq!(tls.certificates[0].cert_path, "/path/to/cert.pem");
    assert_eq!(tls.certificates[0].key_path, "/path/to/key.pem");
    assert!(tls.client_ca_certs.is_none());
  }

  #[test]
  fn test_server_tls_config_deserialize_multiple_certs() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert1.pem"
    key_path: "/path/to/key1.pem"
  - cert_path: "/path/to/cert2.pem"
    key_path: "/path/to/key2.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 2);
  }

  #[test]
  fn test_server_tls_config_deserialize_with_client_ca() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
client_ca_certs:
  - "/path/to/ca1.pem"
  - "/path/to/ca2.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 1);
    assert!(tls.client_ca_certs.is_some());
    let client_cas = tls.client_ca_certs.unwrap();
    assert_eq!(client_cas.len(), 2);
    assert_eq!(client_cas[0], "/path/to/ca1.pem");
    assert_eq!(client_cas[1], "/path/to/ca2.pem");
  }

  #[test]
  fn test_server_tls_config_missing_certificates() {
    let yaml = r#"{}"#;
    let result: Result<ServerTlsConfig, _> = serde_yaml::from_str(yaml);
    // certificates field is required
    assert!(result.is_err());
  }

  #[test]
  fn test_certificate_config_missing_fields() {
    // Missing cert_path
    let yaml = r#"key_path: "/path/to/key.pem""#;
    let result: Result<CertificateConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err());

    // Missing key_path
    let yaml = r#"cert_path: "/path/to/cert.pem""#;
    let result: Result<CertificateConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err());
  }
}

// =========================================================================
// Validation logic
// =========================================================================

/// Validate server-level TLS configuration.
pub fn validate_server_tls(
  tls: &ServerTlsConfig,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if tls.certificates.is_empty() {
    collector.add(ConfigError::InvalidFormat {
      location: format!("{}.certificates", location),
      message: "at least one certificate is required".into(),
    });
    return;
  }

  for (idx, cert) in tls.certificates.iter().enumerate() {
    let cert_location = format!("{}.certificates[{}]", location, idx);

    match fs::read_to_string(std::path::Path::new(&cert.cert_path)) {
      Ok(content) => {
        if !content.contains("-----BEGIN CERTIFICATE-----")
          && !content.contains("-----BEGIN TRUSTED CERTIFICATE-----")
        {
          collector.add(ConfigError::InvalidFormat {
            location: format!("{}.cert_path", cert_location),
            message: format!(
              "certificate file '{}' is not in PEM format",
              cert.cert_path
            ),
          });
        }
      }
      Err(e) => {
        collector.add(ConfigError::FileRead {
          location: format!("{}.cert_path", cert_location),
          message: format!(
            "certificate file '{}' cannot be read: {}",
            cert.cert_path, e
          ),
        });
      }
    }

    match fs::read_to_string(std::path::Path::new(&cert.key_path)) {
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
              cert.key_path
            ),
          });
        }
      }
      Err(e) => {
        collector.add(ConfigError::FileRead {
          location: format!("{}.key_path", cert_location),
          message: format!(
            "private key file '{}' cannot be read: {}",
            cert.key_path, e
          ),
        });
      }
    }
  }
}

#[cfg(test)]
mod validation_tests {
  use super::*;

  #[test]
  fn test_validate_server_tls_empty_certificates() {
    let tls =
      ServerTlsConfig { certificates: vec![], client_ca_certs: None };
    let mut collector = ConfigErrorCollector::new();
    validate_server_tls(&tls, "servers[0].tls", &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| matches!(e, ConfigError::InvalidFormat { .. }));
    assert!(found);
  }

  #[test]
  fn test_validate_server_tls_cert_file_not_found() {
    let tls = ServerTlsConfig {
      certificates: vec![CertificateConfig {
        cert_path: "/nonexistent/path/cert.pem".to_string(),
        key_path: "/nonexistent/path/key.pem".to_string(),
      }],
      client_ca_certs: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_server_tls(&tls, "servers[0].tls", &mut collector);
    assert!(collector.has_errors());
    // Both cert and key should have errors
    assert_eq!(collector.errors().len(), 2);
  }
}
