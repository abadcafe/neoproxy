//! Black-box SNI-to-server selection and configuration compilation
//! contracts.

use std::io::Cursor;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;

use crate::server::{Server, placeholder_service};
use crate::tls::build_tls_server_config;

struct Identity {
  cert: String,
  key: String,
  der: CertificateDer<'static>,
  _directory: tempfile::TempDir,
}

fn identity(names: &[&str]) -> Identity {
  let _ = rustls::crypto::ring::default_provider().install_default();
  let directory = tempfile::tempdir().unwrap();
  let key = rcgen::KeyPair::generate().unwrap();
  let certificate = rcgen::CertificateParams::new(
    names.iter().map(|name| name.to_string()).collect::<Vec<_>>(),
  )
  .unwrap()
  .self_signed(&key)
  .unwrap();
  let cert_path = directory.path().join("cert.pem");
  let key_path = directory.path().join("key.pem");
  std::fs::write(&cert_path, certificate.pem()).unwrap();
  std::fs::write(&key_path, key.serialize_pem()).unwrap();
  Identity {
    cert: cert_path.to_string_lossy().into_owned(),
    key: key_path.to_string_lossy().into_owned(),
    der: certificate.der().clone(),
    _directory: directory,
  }
}

fn server(names: &[&str], identities: &[&Identity]) -> Server {
  let certificates = identities
    .iter()
    .map(|identity| {
      format!(
        "- cert_path: {:?}\n  key_path: {:?}\n",
        identity.cert, identity.key
      )
    })
    .collect::<String>();
  Server {
    hostnames: names.iter().map(|name| name.to_string()).collect(),
    service: placeholder_service(),
    service_name: "selection-test".into(),
    tls: Some(
      serde_yaml::from_str(&format!("certificates:\n{certificates}"))
        .unwrap(),
    ),
  }
}

fn selected(
  config: &rustls::ServerConfig,
  name: Option<&str>,
) -> Option<CertificateDer<'static>> {
  let mut client_config = rustls::ClientConfig::builder()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
  client_config.enable_sni = name.is_some();
  let mut client = rustls::ClientConnection::new(
    Arc::new(client_config),
    rustls::pki_types::ServerName::try_from(
      name.unwrap_or("unused.test").to_owned(),
    )
    .unwrap(),
  )
  .unwrap();
  let mut hello = Vec::new();
  client.write_tls(&mut hello).unwrap();
  let mut acceptor = rustls::server::Acceptor::default();
  acceptor.read_tls(&mut Cursor::new(hello)).unwrap();
  let accepted = acceptor.accept().unwrap().unwrap();
  config
    .cert_resolver
    .resolve(accepted.client_hello())
    .map(|key| key.cert[0].clone())
}

#[test]
fn test_select_does_not_create_routes_from_extra_san() {
  let certificate = identity(&["named.test", "extra.test"]);
  let config = build_tls_server_config(
    &[server(&["named.test"], &[&certificate])],
    vec![],
  )
  .unwrap();
  assert_eq!(
    selected(&config, Some("named.test")),
    Some(certificate.der.clone())
  );
  assert_eq!(selected(&config, Some("extra.test")), None);
}

#[test]
fn test_select_unknown_or_missing_sni_uses_explicit_default() {
  let certificate = identity(&["default.test"]);
  let config =
    build_tls_server_config(&[server(&[], &[&certificate])], vec![])
      .unwrap();
  for name in [None, Some("unknown.test")] {
    assert_eq!(selected(&config, name), Some(certificate.der.clone()));
  }
}

#[test]
fn test_select_named_server_precedes_default_even_when_sans_overlap() {
  let fallback = identity(&["named.test", "default.test"]);
  let named = identity(&["named.test"]);
  let config = build_tls_server_config(
    &[server(&["named.test"], &[&named]), server(&[], &[&fallback])],
    vec![],
  )
  .unwrap();
  assert_eq!(selected(&config, Some("named.test")), Some(named.der));
  assert_eq!(selected(&config, Some("other.test")), Some(fallback.der));
}

#[test]
fn test_select_server_is_independent_of_other_servers_overlapping_sans()
{
  let first = identity(&["first.test", "second.test"]);
  let second = identity(&["first.test", "second.test"]);
  let config = build_tls_server_config(
    &[
      server(&["first.test"], &[&first]),
      server(&["second.test"], &[&second]),
    ],
    vec![],
  )
  .unwrap();
  assert_eq!(selected(&config, Some("first.test")), Some(first.der));
  assert_eq!(selected(&config, Some("second.test")), Some(second.der));
}

#[test]
fn test_select_compatible_candidates_follow_configuration_order() {
  let first = identity(&["named.test"]);
  let second = identity(&["named.test"]);
  let config = build_tls_server_config(
    &[server(&["named.test"], &[&first, &second])],
    vec![],
  )
  .unwrap();
  assert_eq!(selected(&config, Some("named.test")), Some(first.der));
}

#[test]
fn test_compile_rejects_hostname_not_covered_by_certificate() {
  let certificate = identity(&["different.test"]);
  let error = build_tls_server_config(
    &[server(&["named.test"], &[&certificate])],
    vec![],
  )
  .unwrap_err();
  let message = format!("{error:#}");
  assert!(message.contains("named.test"));
  assert!(message.contains(&certificate.cert));
}

#[test]
fn test_compile_checks_every_candidate_certificate() {
  let first = identity(&["named.test"]);
  let second = identity(&["different.test"]);
  assert!(
    build_tls_server_config(
      &[server(&["named.test"], &[&first, &second])],
      vec![]
    )
    .is_err()
  );
}

#[test]
fn test_select_matching_server_without_tls_does_not_use_default_certificate()
 {
  let fallback = identity(&["default.test"]);
  let mut without_tls = server(&["named.test"], &[&fallback]);
  without_tls.tls = None;
  let config = build_tls_server_config(
    &[without_tls, server(&[], &[&fallback])],
    vec![],
  )
  .unwrap();
  assert_eq!(selected(&config, Some("named.test")), None);
}

#[test]
fn test_compile_config_reuses_credentials_and_ca_snapshot_without_files()
 {
  let certificate = identity(&["named.test"]);
  let ca = format!("{}-ca.pem", certificate.cert);
  std::fs::copy(&certificate.cert, &ca).unwrap();
  let config = crate::config::Config::parse_str(&format!(
    "servers:\n- name: named\n  hostnames: [named.test]\n  tls:\n    \
     certificates:\n    - cert_path: {:?}\n      key_path: {:?}\n    \
     client_ca_certs: [{:?}]\n",
    certificate.cert, certificate.key, ca,
  ))
  .unwrap();
  config.compile_tls().unwrap();
  std::fs::remove_file(&certificate.cert).unwrap();
  std::fs::remove_file(&certificate.key).unwrap();
  std::fs::remove_file(&ca).unwrap();
  config.clone().compile_tls().unwrap();
  let configured = &config.servers()[0];
  let server = Server {
    hostnames: configured.hostnames().to_vec(),
    service: placeholder_service(),
    service_name: "compiled".into(),
    tls: configured.tls().cloned(),
  };
  let config = build_tls_server_config(&[server], vec![]).unwrap();
  assert_eq!(
    selected(&config, Some("named.test")),
    Some(certificate.der)
  );
}
