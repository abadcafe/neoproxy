use std::path::Path;

use super::server_fixtures::{
  no_tls_servers, plain_servers, tls_servers,
};

#[test]
fn test_plain_servers_returns_single_default_server() {
  let servers = plain_servers();

  assert_eq!(servers.len(), 1);
  assert_eq!(servers[0].service_name, "test");
  assert!(servers[0].hostnames.is_empty());
  assert!(servers[0].tls.is_none());
}

#[test]
fn test_no_tls_servers_returns_server_without_tls() {
  let servers = no_tls_servers();

  assert_eq!(servers.len(), 1);
  assert!(servers[0].tls.is_none());
}

#[test]
fn test_tls_servers_returns_server_with_readable_certificate_files() {
  let servers = tls_servers();
  let tls = servers[0].tls.as_ref().unwrap();
  let certificate = &tls.certificates()[0];

  assert_eq!(servers.len(), 1);
  assert_eq!(servers[0].hostnames, ["test.local".to_string()]);
  assert!(Path::new(certificate.cert_path()).exists());
  assert!(Path::new(certificate.key_path()).exists());
}
