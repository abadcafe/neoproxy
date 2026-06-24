//! Listener configuration types.
//!
//! This module provides:
//! - `ListenerConfig` - Top-level listener configuration
//! - `AddressUsage` - Address usage info for conflict detection
//! - `TransportLayer` - Transport protocol type (TCP/UDP)
//! - `ListenerPropertyValues` - Listener property values for validation
//! - `ListenerPropertiesProvider` - Trait for querying listener props
//!
//! Validation functions are in `config::listener_validation`.

use serde::Deserialize;

use super::SerializedArgs;

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
  /// Whether the listener supports hostname-based routing
  pub(in crate::config) supports_hostname_routing: bool,
}

impl ListenerPropertyValues {
  pub(crate) fn new(
    transport_layer: TransportLayer,
    supports_hostname_routing: bool,
  ) -> Self {
    Self { transport_layer, supports_hostname_routing }
  }

  pub(crate) fn transport_layer(&self) -> TransportLayer {
    self.transport_layer
  }

  pub(crate) fn supports_hostname_routing(&self) -> bool {
    self.supports_hostname_routing
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
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ListenerConfig {
  pub(in crate::config) name: String,
  pub(in crate::config) kind: String,
  pub(in crate::config) addresses: Vec<String>,
  pub(in crate::config) args: SerializedArgs,
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

/// Address usage info for conflict detection.
pub(super) struct AddressUsage {
  pub(super) server_name: String,
  pub(super) listener_kind: String,
  /// Hostnames for this server (empty = default server)
  pub(super) hostnames: Vec<String>,
}
