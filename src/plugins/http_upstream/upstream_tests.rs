use std::rc::Rc;

use super::config::{self, HttpUpstreamPluginConfig};
use super::upstream::UpstreamRegistry;
use crate::tracker::StreamTracker;

#[test]
fn test_upstream_registry_new_accepts_empty_direct_registry() {
  let _ = rustls::crypto::ring::default_provider().install_default();
  let config: HttpUpstreamPluginConfig =
    serde_yaml::from_str("upstreams:\n  - name: direct\n").unwrap();
  let upstreams = config::merge_chain_config(&config).unwrap();

  let registry = UpstreamRegistry::new(
    upstreams,
    None,
    Rc::new(StreamTracker::new()),
  )
  .unwrap();

  assert_eq!(registry.len(), 1);
  assert!(registry.contains_upstream("direct"));
  assert!(!registry.contains_upstream("missing"));
}

#[test]
fn test_upstream_registry_new_rejects_explicit_ca_without_certificates()
{
  let _ = rustls::crypto::ring::default_provider().install_default();
  let directory = tempfile::tempdir().unwrap();
  let path = directory.path().join("server-ca.pem");
  let config: HttpUpstreamPluginConfig =
    serde_yaml::from_str("upstreams: []").unwrap();
  for contents in [
    "",
    " \n\t",
    "not a certificate",
    "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
  ] {
    std::fs::write(&path, contents).unwrap();
    let certificates = config::CertificateConfig {
      server_ca_path: Some(path.to_str().unwrap().into()),
      client_cert_path: None,
      client_key_path: None,
    };
    let result = UpstreamRegistry::new(
      config::merge_chain_config(&config).unwrap(),
      Some(&certificates),
      Rc::new(StreamTracker::new()),
    );
    let error = match result {
      Ok(_) => panic!("explicit CA without certificates was accepted"),
      Err(error) => error,
    };
    assert!(format!("{error:#}").contains("no certificates"));
    assert!(format!("{error:#}").contains(path.to_str().unwrap()));
  }
}
