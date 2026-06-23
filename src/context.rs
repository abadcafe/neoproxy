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
