//! Black-box tests for the context module.

use std::net::SocketAddr;

use crate::context::{
  KEY_CLIENT_IP, KEY_CLIENT_PORT, KEY_SERVER_IP, KEY_SERVER_PORT,
  KEY_SERVICE_NAME, RequestContext, build_request_context,
  get_server_id,
};

#[test]
fn test_new_is_empty() {
  let ctx = RequestContext::new();
  assert!(ctx.get("key").is_none());
}

#[test]
fn test_insert_and_get() {
  let ctx = RequestContext::new();
  ctx.insert("user", "admin");
  assert_eq!(ctx.get("user"), Some("admin".to_string()));
}

#[test]
fn test_insert_overwrites() {
  let ctx = RequestContext::new();
  ctx.insert("key", "v1");
  ctx.insert("key", "v2");
  assert_eq!(ctx.get("key"), Some("v2".to_string()));
}

#[test]
fn test_clone_shares_data() {
  let ctx1 = RequestContext::new();
  ctx1.insert("key", "value");
  let ctx2 = ctx1.clone();
  // Both see the same data
  assert_eq!(ctx2.get("key"), Some("value".to_string()));
  // Mutation through one is visible through the other
  ctx2.insert("key", "new_value");
  assert_eq!(ctx1.get("key"), Some("new_value".to_string()));
}

#[test]
fn test_default() {
  let ctx = RequestContext::default();
  assert!(ctx.get("any").is_none());
}

#[test]
fn test_insert_different_value_types() {
  let ctx = RequestContext::new();
  ctx.insert("port", 8080u16);
  ctx.insert("duration", 42u64);
  assert_eq!(ctx.get("port"), Some("8080".to_string()));
  assert_eq!(ctx.get("duration"), Some("42".to_string()));
}

// ============== build_request_context Tests ==============

#[test]
fn test_build_request_context_has_required_keys() {
  let peer_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
  let local_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
  let service_name = "web_service";

  let ctx =
    build_request_context(&peer_addr, &local_addr, service_name);

  assert_eq!(ctx.get(KEY_CLIENT_IP), Some("192.168.1.100".to_string()));
  assert_eq!(ctx.get(KEY_CLIENT_PORT), Some("54321".to_string()));
  assert_eq!(ctx.get(KEY_SERVER_IP), Some("10.0.0.1".to_string()));
  assert_eq!(ctx.get(KEY_SERVER_PORT), Some("8080".to_string()));
  assert_eq!(
    ctx.get(KEY_SERVICE_NAME),
    Some("web_service".to_string())
  );
}

// ============== get_server_id Tests ==============

#[test]
fn test_get_server_id_returns_ip_port() {
  let ctx = RequestContext::new();
  ctx.insert(KEY_SERVER_IP, "10.0.0.1");
  ctx.insert(KEY_SERVER_PORT, "8080");
  assert_eq!(get_server_id(&ctx), Some("10.0.0.1:8080".to_string()));
}

#[test]
fn test_get_server_id_missing_ip() {
  let ctx = RequestContext::new();
  ctx.insert(KEY_SERVER_PORT, "8080");
  assert_eq!(get_server_id(&ctx), None);
}

#[test]
fn test_get_server_id_missing_port() {
  let ctx = RequestContext::new();
  ctx.insert(KEY_SERVER_IP, "10.0.0.1");
  assert_eq!(get_server_id(&ctx), None);
}

#[test]
fn test_get_server_id_empty_context() {
  let ctx = RequestContext::new();
  assert_eq!(get_server_id(&ctx), None);
}
