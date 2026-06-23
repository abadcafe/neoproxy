//! Black-box tests for the socks5 listener module.
//!
//! Error type tests (HandshakeError, CommandError) are in the
//! submodule test files: socks5/handshake_tests.rs and
//! socks5/command_tests.rs.

use super::test_helpers::{empty_args, test_servers};
use crate::listeners::socks5;

// ========== listener_name ==========

#[test]
fn test_socks5_listener_name_returns_socks5() {
  assert_eq!(socks5::listener_name(), "socks5");
}

// ========== props ==========

#[test]
fn test_socks5_listener_props_tcp_without_hostname_routing() {
  let props = socks5::props();
  assert_eq!(
    props.transport_layer(),
    crate::listener::TransportLayer::Tcp
  );
  assert!(!props.supports_hostname_routing());
}

// ========== create_listener_builder ==========

#[test]
fn test_socks5_builder_valid_address_succeeds() {
  let builder = socks5::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_socks5_builder_invalid_address_returns_error() {
  let builder = socks5::create_listener_builder();
  let result = builder(
    vec!["invalid_address".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_err());
}

#[test]
fn test_socks5_builder_default_args_succeeds() {
  let builder = socks5::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_socks5_builder_custom_handshake_timeout_succeeds() {
  let builder = socks5::create_listener_builder();
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(r#"handshake_timeout: "5s""#).unwrap();
  let result =
    builder(vec!["127.0.0.1:0".to_string()], args, test_servers());
  assert!(result.is_ok());
}

#[test]
fn test_socks5_builder_invalid_handshake_timeout_returns_error() {
  let builder = socks5::create_listener_builder();
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(r#"handshake_timeout: "not_a_duration""#)
      .unwrap();
  let result =
    builder(vec!["127.0.0.1:0".to_string()], args, test_servers());
  assert!(result.is_err());
}

#[test]
fn test_socks5_builder_unknown_yaml_field_rejected() {
  let builder = socks5::create_listener_builder();
  let args: crate::config::SerializedArgs =
    serde_yaml::from_str(r#"unknown_field: true"#).unwrap();
  let result =
    builder(vec!["127.0.0.1:0".to_string()], args, test_servers());
  assert!(result.is_err());
}

#[test]
fn test_socks5_builder_empty_routing_table_succeeds() {
  let builder = socks5::create_listener_builder();
  let result =
    builder(vec!["127.0.0.1:0".to_string()], empty_args(), vec![]);
  assert!(result.is_ok());
}

#[test]
fn test_socks5_builder_multiple_addresses_succeeds() {
  let builder = socks5::create_listener_builder();
  let result = builder(
    vec!["127.0.0.1:0".to_string(), "127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_ok());
}

#[test]
fn test_socks5_builder_ipv6_address_succeeds() {
  let builder = socks5::create_listener_builder();
  let result =
    builder(vec!["[::1]:0".to_string()], empty_args(), test_servers());
  assert!(result.is_ok());
}
