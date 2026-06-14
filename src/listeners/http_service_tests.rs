//! Black-box tests for http_service module.
//!
//! `HttpServiceAdaptor::call()` implements `hyper::Service` and accepts
//! `hyper::body::Incoming` which cannot be constructed outside hyper.
//! The `call()` behavior is covered by integration tests in
//! `tests/integration/test_h1_h3_consistency.py`:
//!
//! - Routing: `test_http10_get_with_host_routed`
//! - Missing Host: `test_http10_get_without_host_returns_400`,
//!   `test_http_missing_host_returns_400`
//! - Authority/Host mismatch:
//!   `test_h3_authority_host_mismatch_returns_400`
//! - mTLS required but no cert: `test_https_no_cert_returns_403`,
//!   `test_h3_no_cert_returns_403`
//! - mTLS with valid cert: `test_https_with_cert_returns_200`

use std::net::SocketAddr;

use crate::listeners::http_service::HttpServiceAdaptor;
use crate::server::Server;

fn test_servers() -> Vec<Server> {
  vec![Server {
    hostnames: vec![],
    service: crate::server::placeholder_service(),
    service_name: "test".to_string(),
    tls: None,
  }]
}

fn multi_servers() -> Vec<Server> {
  vec![
    Server {
      hostnames: vec![],
      service: crate::server::placeholder_service(),
      service_name: "default".to_string(),
      tls: None,
    },
    Server {
      hostnames: vec!["api.example.com".to_string()],
      service: crate::server::placeholder_service(),
      service_name: "api".to_string(),
      tls: None,
    },
  ]
}

#[test]
fn test_http_service_adaptor_new_http_succeeds() {
  let _adaptor = HttpServiceAdaptor::new_http(
    test_servers(),
    None,
    None,
  );
}

#[test]
fn test_http_service_adaptor_new_https_succeeds() {
  let _adaptor = HttpServiceAdaptor::new_https(
    test_servers(),
    None,
    None,
    false,
  );
}

#[test]
fn test_http_service_adaptor_new_http_with_addrs() {
  let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
  let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
  let _adaptor = HttpServiceAdaptor::new_http(
    test_servers(),
    Some(peer),
    Some(local),
  );
}

#[test]
fn test_http_service_adaptor_new_https_with_client_cert() {
  let _adaptor = HttpServiceAdaptor::new_https(
    test_servers(),
    None,
    None,
    true, // client cert presented
  );
}

#[test]
fn test_http_service_adaptor_new_http_multi_servers() {
  let _adaptor = HttpServiceAdaptor::new_http(
    multi_servers(),
    None,
    None,
  );
}
