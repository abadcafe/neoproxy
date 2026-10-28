//! Public deserialization contracts for flat virtual-server identities.

use crate::config::Server;

#[test]
fn test_server_flat_certificates_and_client_ca() {
  let server: Server = serde_yaml::from_str(
    r#"
name: main
listeners: [https, http3]
service: proxy
certificates:
- cert_path: server.pem
  key_path: server.key
- cert_path: alternate.pem
  key_path: alternate.key
client_ca_certs: [clients.pem]
"#,
  )
  .unwrap();
  let tls = server.tls().unwrap();
  assert_eq!(tls.certificates().len(), 2);
  assert_eq!(tls.certificates()[0].cert_path(), "server.pem");
  assert_eq!(tls.certificates()[1].key_path(), "alternate.key");
  assert_eq!(tls.client_ca_certs(), &["clients.pem"]);
  assert_eq!(server.listeners(), &["https", "http3"]);
}

#[test]
fn test_server_flat_certificates_default_optional_client_auth() {
  let server: Server = serde_yaml::from_str(
    "certificates:\n- cert_path: server.pem\n  key_path: server.key",
  )
  .unwrap();
  assert!(server.tls().unwrap().client_ca_certs().is_empty());
}

#[test]
fn test_server_without_certificate_fields_has_no_tls_identity() {
  let server: Server = serde_yaml::from_str("name: plain").unwrap();
  assert!(server.tls().is_none());
}

#[test]
fn test_server_empty_or_incomplete_identity_is_retained_for_validation()
{
  for yaml in ["certificates: []", "client_ca_certs: [clients.pem]"] {
    let server: Server = serde_yaml::from_str(yaml).unwrap();
    assert!(server.tls().unwrap().certificates().is_empty());
  }
}

#[test]
fn test_server_rejects_unknown_fields_and_invalid_certificate_shapes() {
  for yaml in [
    "unknown: true",
    "certificates: [{cert_path: cert.pem}]",
    "certificates: [{cert_path: cert.pem, key_path: cert.key, \
     unknown: true}]",
    "client_ca_certs: invalid",
  ] {
    assert!(serde_yaml::from_str::<Server>(yaml).is_err(), "{yaml}");
  }
}
