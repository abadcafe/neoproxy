//! Black-box tests for the tls module.

use std::sync::OnceLock;

use rustls::pki_types::CertificateDer;

use crate::config::{CertificateConfig, ServerTlsConfig};
use crate::server::{Server, placeholder_service};
use crate::tls::{
  build_tls_server_config, extract_san_dns_names, load_cert_and_key,
};

static CRYPTO_PROVIDER_INSTALLED: OnceLock<bool> = OnceLock::new();

/// Ensure the rustls crypto provider is installed for tests.
fn ensure_crypto_provider() {
  CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
    true
  });
}

/// Generate a test certificate with specified SAN entries.
fn generate_test_cert_with_san(
  san_entries: Vec<String>,
) -> (String, String, tempfile::TempDir) {
  ensure_crypto_provider();
  let temp_dir = tempfile::tempdir().unwrap();

  let key_pair = rcgen::KeyPair::generate().unwrap();
  let mut params =
    rcgen::CertificateParams::new(san_entries.clone()).unwrap();
  params.is_ca = rcgen::IsCa::NoCa;
  params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
  params.extended_key_usages =
    vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
  params.distinguished_name = rcgen::DistinguishedName::new();
  params
    .distinguished_name
    .push(rcgen::DnType::CommonName, "test.local");

  let cert = params.self_signed(&key_pair).unwrap();
  let cert_pem = cert.pem();
  let key_pem = key_pair.serialize_pem();

  let cert_path = temp_dir.path().join("test_cert.pem");
  let key_path = temp_dir.path().join("test_key.pem");

  std::fs::write(&cert_path, cert_pem).unwrap();
  std::fs::write(&key_path, key_pem).unwrap();

  (
    cert_path.to_str().unwrap().to_string(),
    key_path.to_str().unwrap().to_string(),
    temp_dir,
  )
}

#[test]
fn test_extract_san_from_certificate() {
  ensure_crypto_provider();

  let (cert_path, _key_path, _temp_dir) =
    generate_test_cert_with_san(vec![
      "test.example.com".to_string(),
      "api.example.com".to_string(),
    ]);

  let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
  let cert_der = rustls_pemfile::certs(&mut std::io::Cursor::new(
    cert_pem.as_bytes(),
  ))
  .next()
  .unwrap()
  .unwrap();

  let san_names = extract_san_dns_names(&cert_der).unwrap();

  assert!(san_names.contains(&"test.example.com".to_string()));
  assert!(san_names.contains(&"api.example.com".to_string()));
}

#[test]
fn test_extract_san_empty_cert() {
  ensure_crypto_provider();

  let empty_cert = CertificateDer::from(vec![]);
  let result = extract_san_dns_names(&empty_cert);
  assert!(result.is_err());
}

#[test]
fn test_load_cert_and_key_missing_file() {
  ensure_crypto_provider();

  let config = CertificateConfig {
    cert_path: "/nonexistent/path/cert.pem".to_string(),
    key_path: "/nonexistent/path/key.pem".to_string(),
  };
  let result = load_cert_and_key(&config);
  assert!(result.is_err());
}

#[test]
fn test_build_tls_server_config_with_multiple_servers() {
  ensure_crypto_provider();

  let (cert_path1, key_path1, _temp_dir1) =
    generate_test_cert_with_san(vec!["app1.example.com".to_string()]);
  let (cert_path2, key_path2, _temp_dir2) =
    generate_test_cert_with_san(vec!["app2.example.com".to_string()]);

  let servers = vec![
    Server {
      hostnames: vec!["app1.example.com".to_string()],
      service: placeholder_service(),
      service_name: "server1".to_string(),
      tls: Some(ServerTlsConfig {
        certificates: vec![CertificateConfig {
          cert_path: cert_path1,
          key_path: key_path1,
        }],
        client_ca_certs: None,
      }),
    },
    Server {
      hostnames: vec!["app2.example.com".to_string()],
      service: placeholder_service(),
      service_name: "server2".to_string(),
      tls: Some(ServerTlsConfig {
        certificates: vec![CertificateConfig {
          cert_path: cert_path2,
          key_path: key_path2,
        }],
        client_ca_certs: None,
      }),
    },
  ];

  let result =
    build_tls_server_config(&servers, vec![b"http/1.1".to_vec()]);
  assert!(result.is_ok());

  let config = result.unwrap();
  assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

#[test]
fn test_build_tls_server_config_no_certificates() {
  ensure_crypto_provider();

  let servers: Vec<Server> = vec![];

  let result =
    build_tls_server_config(&servers, vec![b"http/1.1".to_vec()]);
  assert!(result.is_ok());
}
