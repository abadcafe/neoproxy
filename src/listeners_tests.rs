//! Black-box tests for the listeners module (ListenerManager).

use crate::config::{ListenerPropertiesProvider, TransportLayer};
use crate::listeners::ListenerManager;
use crate::listeners::test_helpers::{
  empty_args, test_servers, tls_servers,
};

// ========== ListenerManager::new registration ==========

#[test]
fn test_listener_manager_new_registers_http() {
  let lm = ListenerManager::new();
  let result = lm.build_listener(
    "http",
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_ok(), "http listener should be registered");
}

#[test]
fn test_listener_manager_new_registers_socks5() {
  let lm = ListenerManager::new();
  let result = lm.build_listener(
    "socks5",
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_ok(), "socks5 listener should be registered");
}

#[test]
fn test_listener_manager_new_registers_https() {
  let lm = ListenerManager::new();
  let result = lm.build_listener(
    "https",
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok(), "https listener should be registered");
}

#[test]
fn test_listener_manager_new_registers_http3() {
  let lm = ListenerManager::new();
  let result = lm.build_listener(
    "http3",
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    tls_servers(),
  );
  assert!(result.is_ok(), "http3 listener should be registered");
}

// ========== build_listener error paths ==========

#[test]
fn test_listener_manager_build_unknown_kind_returns_error() {
  let lm = ListenerManager::new();
  let result = lm.build_listener(
    "unknown_kind",
    vec!["127.0.0.1:0".to_string()],
    empty_args(),
    test_servers(),
  );
  assert!(result.is_err());
  assert!(
    result.unwrap_err().to_string().contains("unknown listener kind")
  );
}

// ========== listener_props (ListenerPropertiesProvider trait)
// ==========

#[test]
fn test_listener_manager_http_props_tcp_with_hostname_routing() {
  let lm = ListenerManager::new();
  let props = lm.listener_props("http").unwrap();
  assert_eq!(props.transport_layer, TransportLayer::Tcp);
  assert!(props.supports_hostname_routing);
}

#[test]
fn test_listener_manager_https_props_tcp_with_hostname_routing() {
  let lm = ListenerManager::new();
  let props = lm.listener_props("https").unwrap();
  assert_eq!(props.transport_layer, TransportLayer::Tcp);
  assert!(props.supports_hostname_routing);
}

#[test]
fn test_listener_manager_http3_props_udp_with_hostname_routing() {
  let lm = ListenerManager::new();
  let props = lm.listener_props("http3").unwrap();
  assert_eq!(props.transport_layer, TransportLayer::Udp);
  assert!(props.supports_hostname_routing);
}

#[test]
fn test_listener_manager_socks5_props_tcp_without_hostname_routing() {
  let lm = ListenerManager::new();
  let props = lm.listener_props("socks5").unwrap();
  assert_eq!(props.transport_layer, TransportLayer::Tcp);
  assert!(!props.supports_hostname_routing);
}

#[test]
fn test_listener_manager_deprecated_kinds_not_registered() {
  let lm = ListenerManager::new();
  assert!(lm.listener_props("hyper.listener").is_none());
  assert!(lm.listener_props("http3.listener").is_none());
  assert!(lm.listener_props("fast_socks5.listener").is_none());
}

#[test]
fn test_listener_manager_unknown_kind_returns_none() {
  let lm = ListenerManager::new();
  assert!(lm.listener_props("nonexistent").is_none());
}
