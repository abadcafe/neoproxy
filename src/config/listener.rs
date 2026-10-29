//! module: config::listener
//! responsibility: describe configured listeners through a consumer-
//! owned property contract
//! public operations: TransportLayer, ListenerPropertyValues, new,
//! transport_layer,
//! requires_server_certificate, ListenerPropertiesProvider,
//! ListenerConfig, name, kind, addresses, args
//! data entities: TransportLayer, ListenerPropertyValues,
//! ListenerConfig
//! tests: listener_tests.rs, listener_validation_conflict_tests.rs,
//! listener_validation_test_support_tests.rs,
//! listener_validation_tests.rs

//! Listener configuration types.
//!
//! This module provides:
//! - `ListenerConfig` - Top-level listener configuration
//! - `TransportLayer` - Transport protocol type (TCP/UDP)
//! - `ListenerPropertyValues` - Listener property values for validation
//! - `ListenerPropertiesProvider` - Trait for querying listener props
//!
//! Validation functions are in `config::listener_validation`.

use serde::Deserialize;

use super::args::SerializedArgs;
use crate::redaction::Redacted;

/// Transport layer protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportLayer {
  /// TCP protocol
  Tcp,
  /// UDP protocol
  Udp,
}

/// Listener property values used by config validation.
///
/// This is a value type extracted from `ListenerProps` by the
/// `ListenerPropertiesProvider` trait, keeping config independent
/// of the listeners module.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ListenerPropertyValues {
  /// Transport layer protocol (TCP or UDP)
  pub(in crate::config) transport_layer: TransportLayer,
  /// Each associated virtual server must own a TLS identity.
  requires_server_certificate: bool,
}

impl ListenerPropertyValues {
  pub(crate) fn new(
    transport_layer: TransportLayer,
    requires_server_certificate: bool,
  ) -> Self {
    Self { transport_layer, requires_server_certificate }
  }

  pub(crate) fn requires_server_certificate(&self) -> bool {
    self.requires_server_certificate
  }

  pub(crate) fn transport_layer(&self) -> TransportLayer {
    self.transport_layer
  }
}

/// Abstraction for querying listener properties during config
/// validation.
///
/// Defined in the config module (the using side) per DIP, so that
/// config does not depend on the listeners module. The listeners
/// module implements this trait for `ListenerManager`.
pub(crate) trait ListenerPropertiesProvider {
  /// Get properties for a listener kind, if registered.
  fn listener_props(
    &self,
    kind: &str,
  ) -> Option<ListenerPropertyValues>;
}

/// Top-level listener configuration.
#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub(crate) struct ListenerConfig {
  pub(in crate::config) name: String,
  pub(in crate::config) kind: String,
  pub(in crate::config) addresses: Vec<String>,
  #[serde(flatten)]
  pub(in crate::config) args: SerializedArgs,
}

impl std::fmt::Debug for ListenerConfig {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("ListenerConfig")
      .field("name", &self.name)
      .field("kind", &self.kind)
      .field("addresses", &self.addresses)
      .field("args", &Redacted(&self.args))
      .finish()
  }
}

impl ListenerConfig {
  pub(crate) fn name(&self) -> &str {
    &self.name
  }

  pub(crate) fn kind(&self) -> &str {
    &self.kind
  }

  pub(crate) fn addresses(&self) -> &[String] {
    &self.addresses
  }

  pub(crate) fn args(&self) -> &SerializedArgs {
    &self.args
  }
}
