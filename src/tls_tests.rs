//! Black-box tests for the tls module.

use std::sync::OnceLock;

use crate::config::ServerTlsConfig;
use crate::server::Server;
use crate::server_fixtures::placeholder_service;
use crate::tls::build_tls_server_config;

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

fn server_tls_config(
  cert_path: String,
  key_path: String,
) -> ServerTlsConfig {
  serde_yaml::from_str(&format!(
    "certificates:\n- cert_path: {cert_path:?}\n  key_path: \
     {key_path:?}\n"
  ))
  .unwrap()
}

fn server_with_ca_files(
  cert_path: &str,
  key_path: &str,
  ca_paths: &[&str],
) -> Server {
  let ca_paths = ca_paths
    .iter()
    .map(|path| format!("{path:?}"))
    .collect::<Vec<_>>()
    .join(", ");
  Server {
    hostnames: vec![],
    service: placeholder_service(),
    service_name: "ca-test".into(),
    tls: Some(
      serde_yaml::from_str(&format!(
        "certificates:\n- cert_path: {cert_path:?}\n  key_path: \
         {key_path:?}\nclient_ca_certs: [{ca_paths}]\n"
      ))
      .unwrap(),
    ),
  }
}

#[test]
fn test_build_tls_server_config_empty_client_ca_list() {
  let (cert, key, _directory) =
    generate_test_cert_with_san(vec!["localhost".into()]);
  let server = server_with_ca_files(&cert, &key, &[]);
  assert!(
    build_tls_server_config(&[server], vec![b"http/1.1".to_vec()])
      .is_ok()
  );
}

#[test]
fn test_build_tls_server_config_rejects_ca_file_without_certificates() {
  let (cert, key, directory) =
    generate_test_cert_with_san(vec!["localhost".into()]);
  let bad = directory.path().join("bad-ca.pem");
  let bad_path = bad.to_str().unwrap();
  let private_key = std::fs::read_to_string(&key).unwrap();
  for content in ["", " \n\t", "not a certificate\n", &private_key] {
    std::fs::write(&bad, content).unwrap();
    // A valid file must not hide an empty input in either order.
    for paths in [[bad_path, &cert], [&cert, bad_path]] {
      let server = server_with_ca_files(&cert, &key, &paths);
      let error =
        build_tls_server_config(&[server], vec![b"http/1.1".to_vec()])
          .unwrap_err();
      let message = format!("{error:#}");
      assert!(message.contains(bad_path), "{message}");
      assert!(message.contains("client_ca_certs["), "{message}");
      assert!(message.contains("no certificates"), "{message}");
    }
  }
}

#[test]
fn test_build_tls_server_config_other_server_cannot_hide_empty_ca_file()
{
  let (cert, key, directory) =
    generate_test_cert_with_san(vec!["localhost".into()]);
  let empty = directory.path().join("empty-ca.pem");
  std::fs::write(&empty, "").unwrap();
  let servers = [
    server_with_ca_files(&cert, &key, &[&cert]),
    server_with_ca_files(&cert, &key, &[empty.to_str().unwrap()]),
  ];
  let error =
    build_tls_server_config(&servers, vec![b"http/1.1".to_vec()])
      .unwrap_err();
  let message = format!("{error:#}");
  assert!(message.contains("empty-ca.pem"), "{message}");
  assert!(message.contains("TLS server[1]"), "{message}");
  assert!(message.contains("client_ca_certs[0]"), "{message}");
}

#[test]
fn test_build_tls_server_config_accepts_ca_bundle_with_other_content() {
  let (cert, key, directory) =
    generate_test_cert_with_san(vec!["localhost".into()]);
  let bundle = directory.path().join("bundle.pem");
  let certificate = std::fs::read_to_string(&cert).unwrap();
  let private_key = std::fs::read_to_string(&key).unwrap();
  std::fs::write(
    &bundle,
    format!("# CA bundle\n{certificate}{private_key}{certificate}"),
  )
  .unwrap();
  let server =
    server_with_ca_files(&cert, &key, &[bundle.to_str().unwrap()]);
  assert!(
    build_tls_server_config(&[server], vec![b"http/1.1".to_vec()])
      .is_ok()
  );
}

#[test]
fn test_build_tls_server_config_identifies_ca_read_parse_and_der_errors()
 {
  let (cert, key, directory) =
    generate_test_cert_with_san(vec!["localhost".into()]);
  let bad = directory.path().join("bad-ca.pem");
  let contents = [
    None,
    Some(
      "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
    ),
    Some(
      "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
    ),
  ];
  for content in contents {
    if let Some(content) = content {
      std::fs::write(&bad, content).unwrap();
    }
    let server =
      server_with_ca_files(&cert, &key, &[bad.to_str().unwrap()]);
    let error =
      build_tls_server_config(&[server], vec![b"http/1.1".to_vec()])
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("bad-ca.pem"), "{message}");
    assert!(message.contains("client_ca_certs[0]"), "{message}");
    assert!(message.contains("TLS server[0]"), "{message}");
  }
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
      tls: Some(server_tls_config(cert_path1, key_path1)),
    },
    Server {
      hostnames: vec!["app2.example.com".to_string()],
      service: placeholder_service(),
      service_name: "server2".to_string(),
      tls: Some(server_tls_config(cert_path2, key_path2)),
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
  assert!(result.is_err());
}

fn accepts_client_hello(
  config: std::sync::Arc<rustls::ServerConfig>,
  hostname: &str,
) -> bool {
  let client_config = rustls::ClientConfig::builder()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
  let mut client = rustls::ClientConnection::new(
    std::sync::Arc::new(client_config),
    rustls::pki_types::ServerName::try_from(hostname.to_owned())
      .unwrap(),
  )
  .unwrap();
  let mut hello = Vec::new();
  client.write_tls(&mut hello).unwrap();
  let mut server = rustls::ServerConnection::new(config).unwrap();
  server.read_tls(&mut std::io::Cursor::new(hello)).unwrap();
  server.process_new_packets().is_ok()
}

#[test]
fn test_build_tls_server_config_wildcard_matches_exactly_one_label() {
  let (cert, key, _directory) =
    generate_test_cert_with_san(vec!["*.example.com".into()]);
  let server = Server {
    hostnames: vec!["*.example.com".into()],
    service: placeholder_service(),
    service_name: "wildcard".into(),
    tls: Some(server_tls_config(cert, key)),
  };
  let config =
    build_tls_server_config(&[server], vec![b"http/1.1".to_vec()])
      .unwrap();
  assert!(accepts_client_hello(config.clone(), "API.EXAMPLE.COM"));
  assert!(!accepts_client_hello(config.clone(), "example.com"));
  assert!(!accepts_client_hello(config, "nested.api.example.com"));
}

#[test]
fn test_build_tls_server_config_ignores_intermediate_certificate_names()
{
  let (cert, key, _directory) =
    generate_test_cert_with_san(vec!["leaf.example.com".into()]);
  let (intermediate, _, _other_directory) =
    generate_test_cert_with_san(vec![
      "intermediate.example.com".into(),
    ]);
  let chain = std::fs::read_to_string(&cert).unwrap()
    + &std::fs::read_to_string(intermediate).unwrap();
  std::fs::write(&cert, chain).unwrap();
  let server = Server {
    hostnames: vec!["leaf.example.com".into()],
    service: placeholder_service(),
    service_name: "chain".into(),
    tls: Some(server_tls_config(cert, key)),
  };
  let config =
    build_tls_server_config(&[server], vec![b"http/1.1".to_vec()])
      .unwrap();
  assert!(accepts_client_hello(config.clone(), "leaf.example.com"));
  assert!(!accepts_client_hello(config, "intermediate.example.com"));
}
