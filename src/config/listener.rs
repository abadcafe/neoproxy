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
pub enum TransportLayer {
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
pub struct ListenerPropertyValues {
  /// Transport layer protocol (TCP or UDP)
  pub transport_layer: TransportLayer,
  /// Whether the listener supports hostname-based routing
  pub supports_hostname_routing: bool,
}

/// Abstraction for querying listener properties during config
/// validation.
///
/// Defined in the config module (the using side) per DIP, so that
/// config does not depend on the listeners module. The listeners
/// module implements this trait for `ListenerManager`.
pub trait ListenerPropertiesProvider {
  /// Get properties for a listener kind, if registered.
  fn listener_props(&self, kind: &str)
    -> Option<ListenerPropertyValues>;
}

/// Top-level listener configuration.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
  pub name: String,
  pub kind: String,
  pub addresses: Vec<String>,
  pub args: SerializedArgs,
}

/// Address usage info for conflict detection.
pub struct AddressUsage {
  pub server_name: String,
  pub listener_kind: String,
  /// Hostnames for this server (empty = default server)
  pub hostnames: Vec<String>,
}
