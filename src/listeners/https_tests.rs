//! Black-box tests for the https listener module.

use super::listener_args_fixture::empty_args;
use super::server_fixtures::{no_tls_servers, tls_servers};
use crate::listeners::https;

// ========== listener_name ==========

#[test]
fn test_https_listener_name_returns_https() {
  assert_eq!(https::listener_name(), "https");
}

// ========== props ==========

#[test]
fn test_https_listener_props_tcp_with_hostname_routing() {
  let props = https::props();
  assert_eq!(
    props.transport_layer(),
    crate::listener::TransportLayer::Tcp
  );
  assert!(props.supports_hostname_routing());
}

// ========== create_listener_builder ==========

#[test]
fn test_https_builder_no_tls_returns_error() {
  let builder = https::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    no_tls_servers(),
  );
  assert!(result.is_err());
  assert!(result.unwrap_err().to_string().contains(
    "https listener requires server-level tls configuration"
  ));
}

#[test]
fn test_https_builder_valid_tls_succeeds() {
  let builder = https::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_https_builder_custom_handshake_timeout_succeeds() {
  let builder = https::create_listener_builder();
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(r#"tls_handshake_timeout: "10s""#).unwrap();
  let result =
    builder(vec!["127.0.0.1:0".to_string()], args, tls_servers());
  assert!(result.is_ok());
}

#[test]
fn test_https_builder_invalid_address_returns_error() {
  let builder = https::create_listener_builder();
  let result = builder(
    vec!["invalid_address".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_err());
}

#[test]
fn test_https_builder_default_args_succeeds() {
  let builder = https::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_https_builder_unknown_yaml_field_rejected() {
  let builder = https::create_listener_builder();
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(r#"unknown_field: true"#).unwrap();
  let result =
    builder(vec!["127.0.0.1:0".to_string()], args, tls_servers());
  assert!(result.is_err());
}

#[test]
fn test_https_builder_multiple_addresses_succeeds() {
  let builder = https::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string(), "127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_https_builder_ipv6_address_succeeds() {
  let builder = https::create_listener_builder();
  let result =
    builder(vec!["[::1]:0".to_string()], empty_args(), tls_servers());
  assert!(result.is_ok());
}
