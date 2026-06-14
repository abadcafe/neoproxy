//! Black-box tests for the http listener module.

use super::test_helpers::{empty_args, test_servers};
use crate::listeners::http;
use crate::server::Server;

// ========== listener_name ==========

#[test]
fn test_http_listener_name_returns_http() {
  assert_eq!(http::listener_name(), "http");
}

// ========== props ==========

#[test]
fn test_http_listener_props_tcp_with_hostname_routing() {
  let props = http::props();
  assert_eq!(
    props.transport_layer(),
    crate::listener::TransportLayer::Tcp
  );
  assert!(props.supports_hostname_routing());
}

// ========== create_listener_builder ==========

#[test]
fn test_http_builder_valid_address_succeeds() {
  let builder = http::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_http_builder_invalid_address_returns_error() {
  let builder = http::create_listener_builder();
  let result = builder(
    vec!["invalid_address".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_err());
}

#[test]
fn test_http_builder_default_args_succeeds() {
  let builder = http::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_http_builder_multiple_servers_with_hostnames_succeeds() {
  let builder = http::create_listener_builder();
  let servers = vec![
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
  ];
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    servers,
  );
  assert!(result.is_ok());
}
