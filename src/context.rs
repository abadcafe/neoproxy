//! Request-scoped context for loose coupling between layers and
//! services.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Well-known context keys
// ---------------------------------------------------------------------------

/// Client IP address (`"client.ip"`).
pub const KEY_CLIENT_IP: &str = "client.ip";
/// Client port (`"client.port"`).
pub const KEY_CLIENT_PORT: &str = "client.port";
/// Server (local) IP address (`"server.ip"`).
pub const KEY_SERVER_IP: &str = "server.ip";
/// Server (local) port (`"server.port"`).
pub const KEY_SERVER_PORT: &str = "server.port";
/// Service name (`"service.name"`).
pub const KEY_SERVICE_NAME: &str = "service.name";

/// A string-keyed context for request-scoped data.
///
/// Uses `Arc<Mutex>` so that `.cloned()` creates a new handle to
/// the shared data, rather than a deep copy.
#[derive(Clone)]
pub struct RequestContext {
  inner: Arc<Mutex<HashMap<String, String>>>,
}

impl RequestContext {
  pub fn new() -> Self {
    Self { inner: Arc::new(Mutex::new(HashMap::new())) }
  }

  pub fn insert(&self, key: impl Into<String>, value: impl ToString) {
    self
      .inner
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .insert(key.into(), value.to_string());
  }

  pub fn get(&self, key: &str) -> Option<String> {
    self
      .inner
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .get(key)
      .cloned()
  }
}

// ---------------------------------------------------------------------------
// Context builder helpers
// ---------------------------------------------------------------------------

/// Build a `RequestContext` populated with connection-level metadata.
///
/// Inserts `client.ip`, `client.port`, `server.ip`, `server.port`,
/// and `service.name` into a fresh context.
pub fn build_request_context(
  peer_addr: &SocketAddr,
  local_addr: &SocketAddr,
  service_name: &str,
) -> RequestContext {
  let ctx = RequestContext::new();
  ctx.insert(KEY_CLIENT_IP, peer_addr.ip().to_string());
  ctx.insert(KEY_CLIENT_PORT, peer_addr.port().to_string());
  ctx.insert(KEY_SERVER_IP, local_addr.ip().to_string());
  ctx.insert(KEY_SERVER_PORT, local_addr.port().to_string());
  ctx.insert(KEY_SERVICE_NAME, service_name);
  ctx
}

/// Extract the server identifier (`"ip:port"`) from a `RequestContext`.
///
/// Returns `Some("ip:port")` if both `server.ip` and `server.port` are
/// present, `None` otherwise.  Used for the `Proxy-Status` header
/// (RFC 9209).
pub fn get_server_id(ctx: &RequestContext) -> Option<String> {
  let ip = ctx.get(KEY_SERVER_IP)?;
  let port = ctx.get(KEY_SERVER_PORT)?;
  Some(format!("{ip}:{port}"))
}

impl Default for RequestContext {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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

  #[test]
  fn test_handles_poisoned_mutex_get() {
    let ctx = RequestContext::new();
    ctx.insert("key", "value");

    // Poison the mutex by panicking while holding the lock
    let ctx_clone = ctx.clone();
    let _ = std::thread::spawn(move || {
      let _guard = ctx_clone.inner.lock().unwrap();
      panic!("poison the mutex");
    })
    .join();

    // After poison, get should still work (recover from poison)
    assert_eq!(ctx.get("key"), Some("value".to_string()));
  }

  #[test]
  fn test_handles_poisoned_mutex_insert() {
    let ctx = RequestContext::new();
    ctx.insert("before", "poison");

    // Poison the mutex
    let ctx_clone = ctx.clone();
    let _ = std::thread::spawn(move || {
      let _guard = ctx_clone.inner.lock().unwrap();
      panic!("poison the mutex");
    })
    .join();

    // After poison, insert should still work
    ctx.insert("after", "recovery");
    assert_eq!(ctx.get("after"), Some("recovery".to_string()));
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
}
