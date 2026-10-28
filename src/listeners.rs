//! module: listeners
//! responsibility: register listener construction together with
//! validation properties
//! public operations: ListenerManager, new, build_listener
//! data entities: ListenerManager, Registration
//! tests: listeners_tests.rs

//! Listener registry and concrete implementations.
//!
//! This module provides:
//! - `ListenerManager` - Registry of listener builders and properties
//! - Concrete listener implementations (http, https, http3, socks5)
//! - Shared infrastructure (tcp_bind, http_service, header_validation)

use std::collections::HashMap;

use crate::config::{
  ListenerPropertiesProvider, ListenerPropertyValues,
};
use crate::listener::BuildListener;

pub(crate) mod error_response;
mod header_deadline;
#[cfg(test)]
mod header_deadline_tests;
pub(crate) mod header_validation;
pub(crate) mod http;
pub(crate) mod http3;
mod http_connection;
pub(crate) mod http_service;
pub(crate) mod https;
pub(crate) mod socks5;
mod tcp_accept;
#[cfg(test)]
mod tcp_accept_tests;
pub(crate) mod tcp_bind;
pub(crate) mod tcp_listener_base;

/// Registry for listener builders and their properties.
///
/// Provides access to:
/// - `BuildListener` functions for creating listener instances
/// - `ListenerPropertyValues` for conflict detection
pub(crate) struct ListenerManager {
  registrations: HashMap<&'static str, Registration>,
}

struct Registration {
  builder: Box<dyn BuildListener>,
  properties: ListenerPropertyValues,
}

impl ListenerManager {
  pub(crate) fn new() -> Self {
    let registrations = HashMap::from([
      (
        http::listener_name(),
        Registration {
          builder: http::create_listener_builder(),
          properties: http::props(),
        },
      ),
      (
        https::listener_name(),
        Registration {
          builder: https::create_listener_builder(),
          properties: https::props(),
        },
      ),
      (
        http3::listener_name(),
        Registration {
          builder: http3::create_listener_builder(),
          properties: http3::props(),
        },
      ),
      (
        socks5::listener_name(),
        Registration {
          builder: socks5::create_listener_builder(),
          properties: socks5::props(),
        },
      ),
    ]);
    Self { registrations }
  }

  /// Build a listener by kind.
  pub(crate) fn build_listener(
    &self,
    kind: &str,
    addresses: Vec<String>,
    args: crate::config::SerializedArgs,
    servers: Vec<crate::server::Server>,
  ) -> Result<crate::listener::Listener, anyhow::Error> {
    let registration =
      self.registrations.get(kind).ok_or_else(|| {
        anyhow::anyhow!("unknown listener kind '{}'", kind)
      })?;
    (registration.builder)(addresses, args, servers)
  }
}

impl ListenerPropertiesProvider for ListenerManager {
  fn listener_props(
    &self,
    kind: &str,
  ) -> Option<ListenerPropertyValues> {
    self.registrations.get(kind).map(|entry| entry.properties)
  }
}

// Test modules — siblings of http/https/http3/socks5, can only access
// pub/pub(crate) items from those modules (black-box testing).
#[cfg(test)]
mod error_response_tests;
#[cfg(test)]
mod header_validation_tests;
#[cfg(test)]
mod http3_tests;
#[cfg(test)]
mod http_service_tests;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod https_tests;
#[cfg(test)]
pub(crate) mod listener_args_fixture;
#[cfg(test)]
mod listener_args_fixture_tests;
#[cfg(test)]
pub(crate) mod server_fixtures;
#[cfg(test)]
mod server_fixtures_tests;
#[cfg(test)]
mod socks5_tests;
#[cfg(test)]
mod tcp_bind_tests;
#[cfg(test)]
mod tcp_listener_base_tests;

mod http_policy;
#[cfg(test)]
mod http_policy_tests;

mod incoming_body;
#[cfg(test)]
mod incoming_body_tests;

mod http_protocol;
#[cfg(test)]
mod http_protocol_tests;
mod write_deadline;
#[cfg(test)]
mod write_deadline_tests;
