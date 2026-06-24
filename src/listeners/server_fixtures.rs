use std::sync::OnceLock;

use crate::config::{CertificateConfig, ServerTlsConfig};
use crate::server::Server;

pub(crate) fn plain_servers() -> Vec<Server> {
  vec![Server {
    hostnames: vec![],
    service: crate::server::placeholder_service(),
    service_name: "test".to_string(),
    tls: None,
  }]
}

static CRYPTO_PROVIDER_INSTALLED: OnceLock<bool> = OnceLock::new();

fn ensure_crypto_provider() {
  CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
    true
  });
}

fn generate_test_cert() -> (String, String) {
  let key_pair = rcgen::KeyPair::generate().unwrap();
  let mut params = rcgen::CertificateParams::new(vec![
    "test.local".to_string(),
    "127.0.0.1".to_string(),
  ])
  .unwrap();
  params.is_ca = rcgen::IsCa::NoCa;
  params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
  params.extended_key_usages =
    vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
  params.distinguished_name = rcgen::DistinguishedName::new();
  params
    .distinguished_name
    .push(rcgen::DnType::CommonName, "test.local");
  let cert = params.self_signed(&key_pair).unwrap();
  (cert.pem(), key_pair.serialize_pem())
}

pub(crate) fn tls_servers() -> Vec<Server> {
  ensure_crypto_provider();
  let (cert_pem, key_pem) = generate_test_cert();
  let temp_dir = tempfile::tempdir().unwrap();
  let cert_path = temp_dir.path().join("cert.pem");
  let key_path = temp_dir.path().join("key.pem");
  std::fs::write(&cert_path, &cert_pem).unwrap();
  std::fs::write(&key_path, &key_pem).unwrap();
  std::mem::forget(temp_dir);

  vec![Server {
    hostnames: vec!["test.local".to_string()],
    service: crate::server::placeholder_service(),
    service_name: "test".to_string(),
    tls: Some(ServerTlsConfig::new(
      vec![CertificateConfig::new(
        cert_path.to_str().unwrap().to_string(),
        key_path.to_str().unwrap().to_string(),
      )],
      None,
    )),
  }]
}

pub(crate) fn no_tls_servers() -> Vec<Server> {
  vec![Server {
    hostnames: vec![],
    service: crate::server::placeholder_service(),
    service_name: "test".to_string(),
    tls: None,
  }]
}
