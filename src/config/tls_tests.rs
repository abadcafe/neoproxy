use super::tls::*;
use super::{ConfigError, ConfigErrorCollector};

#[test]
fn test_certificate_config_deserialize() {
  let yaml = r#"
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
"#;
  let cert: CertificateConfig = serde_yaml::from_str(yaml).unwrap();
  assert_eq!(cert.cert_path(), "/path/to/cert.pem");
  assert_eq!(cert.key_path(), "/path/to/key.pem");
}

#[test]
fn test_server_tls_config_deserialize_single_cert() {
  let yaml = r#"
certificates:
- cert_path: "/path/to/cert.pem"
  key_path: "/path/to/key.pem"
"#;
  let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
  assert_eq!(tls.certificates().len(), 1);
  assert_eq!(tls.certificates()[0].cert_path(), "/path/to/cert.pem");
  assert_eq!(tls.certificates()[0].key_path(), "/path/to/key.pem");
  assert!(tls.client_ca_certs().is_none());
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
  assert_eq!(tls.certificates().len(), 2);
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
  assert_eq!(tls.certificates().len(), 1);
  assert!(tls.client_ca_certs().is_some());
  let client_cas = tls.client_ca_certs().unwrap();
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
  let result: Result<CertificateConfig, _> = serde_yaml::from_str(yaml);
  assert!(result.is_err());

  // Missing key_path
  let yaml = r#"cert_path: "/path/to/cert.pem""#;
  let result: Result<CertificateConfig, _> = serde_yaml::from_str(yaml);
  assert!(result.is_err());
}

#[test]
fn test_validate_server_tls_empty_certificates() {
  let tls: ServerTlsConfig =
    serde_yaml::from_str("certificates: []").unwrap();
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
  let tls: ServerTlsConfig = serde_yaml::from_str(
    r#"
certificates:
- cert_path: "/nonexistent/path/cert.pem"
  key_path: "/nonexistent/path/key.pem"
"#,
  )
  .unwrap();
  let mut collector = ConfigErrorCollector::new();
  validate_server_tls(&tls, "servers[0].tls", &mut collector);
  assert!(collector.has_errors());
  assert_eq!(collector.errors().len(), 2);
}
