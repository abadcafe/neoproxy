//! Black-box tests for the http3 listener module.

use super::test_helpers::{empty_args, no_tls_servers, tls_servers};
use crate::listeners::http3;

// ========== listener_name ==========

#[test]
fn test_http3_listener_name_returns_http3() {
  assert_eq!(http3::listener_name(), "http3");
}

// ========== props ==========

#[test]
fn test_http3_listener_props_udp_with_hostname_routing() {
  let props = http3::props();
  assert_eq!(
    props.transport_layer(),
    crate::listener::TransportLayer::Udp
  );
  assert!(props.supports_hostname_routing());
}

// ========== create_listener_builder ==========

#[test]
fn test_http3_builder_no_tls_returns_error() {
  let builder = http3::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    no_tls_servers(),
  );
  assert!(result.is_err());
  assert!(result.unwrap_err().to_string().contains(
    "http3 listener requires server-level tls configuration"
  ));
}

#[test]
fn test_http3_builder_valid_tls_succeeds() {
  let builder = http3::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_http3_builder_default_quic_config_succeeds() {
  let builder = http3::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_http3_builder_invalid_address_returns_error() {
  let builder = http3::create_listener_builder();
  let result = builder(
    vec!["invalid_address".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_err());
}

#[test]
fn test_http3_builder_unknown_yaml_field_rejected() {
  let builder = http3::create_listener_builder();
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(r#"unknown_field: true"#).unwrap();
  let result =
    builder(vec!["127.0.0.1:0".to_string()], args, tls_servers());
  assert!(result.is_err());
}

#[test]
fn test_http3_builder_multiple_addresses_succeeds() {
  let builder = http3::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string(), "127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_http3_builder_ipv6_address_succeeds() {
  let builder = http3::create_listener_builder();
  let result =
    builder(vec!["[::1]:0".to_string()], empty_args(), tls_servers());
  assert!(result.is_ok());
}
