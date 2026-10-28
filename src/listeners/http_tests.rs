//! Black-box tests for the http listener module.

use super::listener_args_fixture::empty_args;
use super::server_fixtures::plain_servers;
use crate::listeners::http;

#[test]
fn test_http_builder_accept_retry_delay_can_be_configured() {
  let args =
    serde_yaml::from_str("tcp_accept_retry_delay: 250ms").unwrap();
  let result = http::create_listener_builder()(
    vec!["127.0.0.1:0".into()],
    args,
    vec![],
  );
  assert!(result.is_ok(), "{result:?}");
}

#[test]
fn test_http_builder_rejects_invalid_accept_retry_delay() {
  for value in ["0s", "invalid", "18446744073709551615s"] {
    let args = serde_yaml::from_str(&format!(
      "tcp_accept_retry_delay: {value:?}"
    ))
    .unwrap();
    let result = http::create_listener_builder()(
      vec!["127.0.0.1:0".into()],
      args,
      vec![],
    );
    assert!(result.is_err(), "accepted invalid retry delay {value}");
  }
}
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
    plain_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_http_builder_invalid_address_returns_error() {
  let builder = http::create_listener_builder();
  let result = builder(
    vec!["invalid_address".to_string()],
    empty_args(),
    plain_servers(),
  );
  assert!(result.is_err());
}

#[test]
fn test_http_builder_default_args_succeeds() {
  let builder = http::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    plain_servers(),
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
  let result =
    builder(vec!["127.0.0.1:0".to_string()], empty_args(), servers);
  assert!(result.is_ok());
}

#[test]
fn test_http_builder_accepts_http_exchange_policy() {
  let args = serde_yaml::from_str(
    "body_read_timeout: 5s\nwrite_timeout: 10s\nmax_request_headers: \
     20\nmax_request_header_size: 32KiB",
  )
  .unwrap();
  assert!(
    http::create_listener_builder()(
      vec!["127.0.0.1:0".into()],
      args,
      plain_servers()
    )
    .is_ok()
  );
}

#[test]
fn test_http_builder_rejects_invalid_http_exchange_policy() {
  for yaml in [
    "body_read_timeout: 0s",
    "write_timeout: 0s",
    "max_request_headers: 0",
    "max_request_header_size: 0",
    "max_request_header_size: 4GiB",
  ] {
    assert!(
      http::create_listener_builder()(
        vec!["127.0.0.1:0".into()],
        serde_yaml::from_str(yaml).unwrap(),
        plain_servers()
      )
      .is_err(),
      "{yaml}"
    );
  }
}
