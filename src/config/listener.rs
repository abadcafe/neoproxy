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
pub(crate) struct AddressUsage {
  pub server_name: String,
  pub listener_kind: String,
  /// Hostnames for this server (empty = default server)
  pub hostnames: Vec<String>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_transport_layer_equality() {
    assert_eq!(TransportLayer::Tcp, TransportLayer::Tcp);
    assert_eq!(TransportLayer::Udp, TransportLayer::Udp);
    assert_ne!(TransportLayer::Tcp, TransportLayer::Udp);
  }

  #[test]
  fn test_transport_layer_clone() {
    let tcp = TransportLayer::Tcp;
    let cloned = tcp;
    assert_eq!(tcp, cloned);
  }

  #[test]
  fn test_listener_config_default() {
    let lc = ListenerConfig::default();
    assert!(lc.name.is_empty());
    assert!(lc.kind.is_empty());
    assert!(lc.addresses.is_empty());
  }

  #[test]
  fn test_listener_config_deserialize() {
    let yaml = r#"
name: http_main
kind: http
addresses:
  - "0.0.0.0:8080"
"#;
    let lc: ListenerConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(lc.name, "http_main");
    assert_eq!(lc.kind, "http");
    assert_eq!(lc.addresses, vec!["0.0.0.0:8080"]);
  }

  #[test]
  fn test_listener_config_clone() {
    let lc = ListenerConfig {
      name: "test".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      args: SerializedArgs::Null,
    };
    let cloned = lc.clone();
    assert_eq!(cloned.name, "test");
    assert_eq!(cloned.kind, "http");
  }

  #[test]
  fn test_listener_property_values_construction() {
    let props = ListenerPropertyValues {
      transport_layer: TransportLayer::Tcp,
      supports_hostname_routing: true,
    };
    assert_eq!(props.transport_layer, TransportLayer::Tcp);
    assert!(props.supports_hostname_routing);
  }

  #[test]
  fn test_address_usage_construction() {
    let usage = AddressUsage {
      server_name: "server1".to_string(),
      listener_kind: "http".to_string(),
      hostnames: vec!["api.example.com".to_string()],
    };
    assert_eq!(usage.server_name, "server1");
    assert_eq!(usage.listener_kind, "http");
    assert_eq!(usage.hostnames.len(), 1);
  }
}
