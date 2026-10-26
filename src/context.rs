//! module: context
//! responsibility: carry typed connection metadata and plugin fields
//! public operations: RequestContext, build_request_context,
//! get_server_id data entities: RequestContext, ConnectionMetadata
//! tests: context_tests.rs

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Connection metadata is immutable and typed. Plugin fields are the
/// only mutable part of a context; reading an address or service name
/// never locks, allocates, or parses a string.
struct ConnectionMetadata {
  client: SocketAddr,
  server: SocketAddr,
  service: String,
}

/// Typed connection metadata with string-keyed plugin data.
///
/// Uses `Arc<Mutex>` so that `.cloned()` creates a new handle to
/// the shared data, rather than a deep copy.
#[derive(Clone)]
pub(crate) struct RequestContext {
  connection: Option<Arc<ConnectionMetadata>>,
  inner: Arc<Mutex<HashMap<String, String>>>,
}

impl RequestContext {
  pub(crate) fn new() -> Self {
    Self {
      connection: None,
      inner: Arc::new(Mutex::new(HashMap::new())),
    }
  }

  pub(crate) fn insert(
    &self,
    key: impl Into<String>,
    value: impl ToString,
  ) {
    let key = key.into();
    assert!(
      !matches!(
        key.as_str(),
        "client.ip"
          | "client.port"
          | "server.ip"
          | "server.port"
          | "service.name"
      ),
      "connection metadata must be constructed with typed addresses"
    );
    self
      .inner
      .lock()
      .expect("request context lock poisoned")
      .insert(key, value.to_string());
  }

  pub(crate) fn client_addr(&self) -> Option<SocketAddr> {
    self.connection.as_ref().map(|connection| connection.client)
  }

  pub(crate) fn server_addr(&self) -> Option<SocketAddr> {
    self.connection.as_ref().map(|connection| connection.server)
  }

  pub(crate) fn service_name(&self) -> Option<&str> {
    self
      .connection
      .as_ref()
      .map(|connection| connection.service.as_str())
  }

  /// Render metadata only when a configured log field asks for it.
  pub(crate) fn get(&self, key: &str) -> Option<String> {
    match key {
      "client.ip" => {
        return self
          .client_addr()
          .map(|address| address.ip().to_string());
      }
      "client.port" => {
        return self
          .client_addr()
          .map(|address| address.port().to_string());
      }
      "server.ip" => {
        return self
          .server_addr()
          .map(|address| address.ip().to_string());
      }
      "server.port" => {
        return self
          .server_addr()
          .map(|address| address.port().to_string());
      }
      "service.name" => return self.service_name().map(str::to_owned),
      _ => {}
    }
    self
      .inner
      .lock()
      .expect("request context lock poisoned")
      .get(key)
      .cloned()
  }
}

// ---------------------------------------------------------------------------
// Context builder helpers
// ---------------------------------------------------------------------------

/// Build a `RequestContext` populated with connection-level metadata.
///
/// Addresses and service name are immutable for the request lifetime.
pub(crate) fn build_request_context(
  peer_addr: &SocketAddr,
  local_addr: &SocketAddr,
  service_name: &str,
) -> RequestContext {
  RequestContext {
    connection: Some(Arc::new(ConnectionMetadata {
      client: *peer_addr,
      server: *local_addr,
      service: service_name.to_owned(),
    })),
    inner: Arc::new(Mutex::new(HashMap::new())),
  }
}

/// Extract the server identifier (`"ip:port"`) from a `RequestContext`.
///
/// Returns the typed server address, or `None` without a connection.
/// Used for the `Proxy-Status` header
/// (RFC 9209).
pub(crate) fn get_server_id(ctx: &RequestContext) -> Option<String> {
  ctx.server_addr().map(|address| address.to_string())
}

impl Default for RequestContext {
  fn default() -> Self {
    Self::new()
  }
}
