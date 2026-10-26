//! module: context
//! responsibility: carry typed connection metadata and plugin fields
//! public operations: RequestContext, build_request_context,
//! snapshot data entities: RequestContext, ConnectionMetadata
//! tests: context_tests.rs

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
pub(crate) mod fields;
mod key;
pub(crate) mod value;
#[cfg(test)]
mod value_tests;
use key::ContextKey;
use value::{ContextType, ContextValue};

use crate::request_id::RequestId;

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
  request_id: Option<RequestId>,
  inner: Arc<Mutex<HashMap<&'static str, ContextValue>>>,
}

impl RequestContext {
  pub(crate) fn new() -> Self {
    Self {
      connection: None,
      request_id: None,
      inner: Arc::new(Mutex::new(HashMap::new())),
    }
  }

  pub(crate) fn set<T: ContextType>(
    &self,
    key: ContextKey<T>,
    value: T,
  ) {
    self
      .inner
      .lock()
      .expect("request context lock poisoned")
      .insert(key.name, value.into_value());
  }

  pub(crate) fn get<T: ContextType>(
    &self,
    key: ContextKey<T>,
  ) -> Option<T> {
    self
      .inner
      .lock()
      .expect("request context lock poisoned")
      .get(key.name)
      .map(|value| {
        T::from_value(value)
          .expect("declared key must retain its value type")
      })
  }

  pub(crate) fn with_request_id(mut self, id: RequestId) -> Self {
    assert!(self.request_id.is_none(), "request identity is immutable");
    self.request_id = Some(id);
    self
  }

  pub(crate) fn request_id(&self) -> Option<&RequestId> {
    self.request_id.as_ref()
  }

  pub(crate) fn with_service(mut self, service: &str) -> Self {
    let previous = self
      .connection
      .as_ref()
      .expect("routing requires connection metadata");
    self.connection = Some(Arc::new(ConnectionMetadata {
      client: previous.client,
      server: previous.server,
      service: service.to_owned(),
    }));
    self
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

  /// Snapshot only selected values under one lock; formatting is
  /// deferred.
  pub(crate) fn snapshot(
    &self,
    keys: &[String],
  ) -> HashMap<String, ContextValue> {
    let fields =
      self.inner.lock().expect("request context lock poisoned");
    keys
      .iter()
      .filter_map(|key| {
        let value = match key.as_str() {
          "client.ip" => {
            self.client_addr().map(|v| ContextValue::from(v.ip()))
          }
          "client.port" => self
            .client_addr()
            .map(|v| ContextValue::from(u64::from(v.port()))),
          "server.ip" => {
            self.server_addr().map(|v| ContextValue::from(v.ip()))
          }
          "server.port" => self
            .server_addr()
            .map(|v| ContextValue::from(u64::from(v.port()))),
          "service.name" => self.service_name().map(ContextValue::from),
          "request.id" => {
            self.request_id().cloned().map(ContextValue::from)
          }
          _ => fields.get(key.as_str()).cloned(),
        }?;
        Some((key.clone(), value))
      })
      .collect()
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
    request_id: None,
    inner: Arc::new(Mutex::new(HashMap::new())),
  }
}

impl Default for RequestContext {
  fn default() -> Self {
    Self::new()
  }
}
