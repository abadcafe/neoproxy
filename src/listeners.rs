//! Listener registry and concrete implementations.
//!
//! This module provides:
//! - `ListenerManager` - Registry of listener builders and properties
//! - Concrete listener implementations (http, https, http3, socks5)
//! - Shared infrastructure (tcp_bind, http_service, header_validation)

#![allow(clippy::borrowed_box)]
use std::collections::HashMap;
use std::time::Duration;

use crate::config::{
  ListenerPropertiesProvider, ListenerPropertyValues,
};
use crate::listener::{BuildListener, ListenerProps};

/// Shared listener shutdown timeout for all listener types.
pub(crate) const LISTENER_SHUTDOWN_TIMEOUT: Duration =
  Duration::from_secs(3);

pub(crate) mod error_response;
pub(crate) mod header_validation;
pub(crate) mod http;
pub(crate) mod http3;
pub(crate) mod http_service;
pub(crate) mod https;
pub(crate) mod socks5;
pub(crate) mod tcp_bind;
pub(crate) mod tcp_listener_base;

/// Registry for listener builders and their properties.
///
/// Provides access to:
/// - `BuildListener` functions for creating listener instances
/// - `ListenerProps` for conflict detection
pub(crate) struct ListenerManager {
  builders: HashMap<&'static str, Box<dyn BuildListener>>,
  props: HashMap<&'static str, ListenerProps>,
}

impl ListenerManager {
  pub(crate) fn new() -> Self {
    let builders = HashMap::from([
      (
        http::listener_name(),
        Box::new(http::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
      (
        https::listener_name(),
        Box::new(https::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
      (
        http3::listener_name(),
        Box::new(http3::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
      (
        socks5::listener_name(),
        Box::new(socks5::create_listener_builder())
          as Box<dyn BuildListener>,
      ),
    ]);
    let props = HashMap::from([
      (http::listener_name(), http::props()),
      (https::listener_name(), https::props()),
      (http3::listener_name(), http3::props()),
      (socks5::listener_name(), socks5::props()),
    ]);
    Self { builders, props }
  }

  /// Build a listener by kind.
  pub(crate) fn build_listener(
    &self,
    kind: &str,
    addresses: Vec<String>,
    args: crate::config::SerializedArgs,
    servers: Vec<crate::server::Server>,
  ) -> Result<crate::listener::Listener, anyhow::Error> {
    let builder = self.builders.get(kind).ok_or_else(|| {
      anyhow::anyhow!("unknown listener kind '{}'", kind)
    })?;
    builder(addresses, args, servers)
  }
}

impl ListenerPropertiesProvider for ListenerManager {
  fn listener_props(
    &self,
    kind: &str,
  ) -> Option<ListenerPropertyValues> {
    self.props.get(kind).map(|p| {
      ListenerPropertyValues::new(
        p.transport_layer(),
        p.supports_hostname_routing(),
      )
    })
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
pub(crate) mod server_fixtures;
#[cfg(test)]
mod socks5_tests;
#[cfg(test)]
mod tcp_bind_tests;
#[cfg(test)]
mod tcp_listener_base_tests;
