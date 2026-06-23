//! Configuration validation orchestration.

use super::listener::ListenerPropertiesProvider;
use super::listener_validation::{
  validate_address_conflicts, validate_hostname,
  validate_hostname_conflicts, validate_hostname_routing_compatibility,
  validate_listener_addresses, validate_listener_references,
};
use super::service::validate_service;
use super::tls::validate_server_tls;
use super::{Config, ConfigError, ConfigErrorCollector};

/// Validate server_threads global setting.
fn validate_server_threads(
  server_threads: usize,
  collector: &mut ConfigErrorCollector,
) {
  if server_threads == 0 {
    collector.add(ConfigError::InvalidFormat {
      location: "server_threads".into(),
      message: "must be at least 1".into(),
    });
  }
}

/// Validate the entire configuration.
///
/// This function validates:
/// - Global settings (server_threads)
/// - Service references in servers
/// - Hostname patterns
/// - TLS configurations
/// - Listener address format
/// - Listener references
/// - Hostname routing compatibility
/// - Address conflicts across servers
/// - Hostname conflicts across servers
pub fn validate_config(
  config: &Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &dyn ListenerPropertiesProvider,
) {
  // Validate global settings
  validate_server_threads(config.server_threads, collector);

  // Collect all service names for reference validation
  let service_names: std::collections::HashSet<&str> =
    config.services.iter().map(|s| s.name.as_str()).collect();

  // Validate servers
  for (server_idx, server) in config.servers.iter().enumerate() {
    let server_location = format!("servers[{}]", server_idx);

    // Validate hostnames
    for (idx, hostname) in server.hostnames.iter().enumerate() {
      let hostname_location =
        format!("{}.hostnames[{}]", server_location, idx);
      validate_hostname(hostname, &hostname_location, collector);
    }

    // Validate TLS if present
    if let Some(ref tls) = server.tls {
      validate_server_tls(
        tls,
        &format!("{}.tls", server_location),
        collector,
      );
    }

    // Validate service reference
    validate_service(
      &service_names,
      server_idx,
      &server.service,
      collector,
    );
  }

  // Validate listener addresses
  for (idx, listener) in config.listeners.iter().enumerate() {
    let location = format!("listeners[{}]", idx);
    validate_listener_addresses(
      &listener.addresses,
      &location,
      collector,
    );
  }

  // Validate listener references
  validate_listener_references(config, collector);

  // Validate hostname routing compatibility
  validate_hostname_routing_compatibility(
    config,
    collector,
    listener_manager,
  );

  // Validate address conflicts across all servers
  validate_address_conflicts(config, collector, listener_manager);

  // Validate hostname conflicts across servers
  validate_hostname_conflicts(config, collector, listener_manager);
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::listener::ListenerPropertyValues;
  use crate::config::listener::TransportLayer;
  use crate::config::{ListenerConfig, Server, Service};

  /// Mock ListenerPropertiesProvider for tests.
  struct MockListenerProps;

  impl ListenerPropertiesProvider for MockListenerProps {
    fn listener_props(
      &self,
      kind: &str,
    ) -> Option<ListenerPropertyValues> {
      match kind {
        "http" | "https" | "http3" => Some(ListenerPropertyValues {
          transport_layer: TransportLayer::Tcp,
          supports_hostname_routing: true,
        }),
        "socks5" => Some(ListenerPropertyValues {
          transport_layer: TransportLayer::Tcp,
          supports_hostname_routing: false,
        }),
        _ => None,
      }
    }
  }

  #[test]
  fn test_validate_config_valid() {
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![Server {
        name: "server1".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "echo".to_string(),
        tls: None,
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = MockListenerProps;
    validate_config(&config, &mut collector, &lm);
    assert!(
      !collector.has_errors(),
      "Valid config should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_config_empty() {
    let config = Config::default();
    let mut collector = ConfigErrorCollector::new();
    let lm = MockListenerProps;
    validate_config(&config, &mut collector, &lm);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_config_server_threads_zero() {
    let config = Config { server_threads: 0, ..Default::default() };
    let mut collector = ConfigErrorCollector::new();
    let lm = MockListenerProps;
    validate_config(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      matches!(e, ConfigError::InvalidFormat { location, .. } if location == "server_threads")
    });
    assert!(found, "Should have server_threads validation error");
  }

  #[test]
  fn test_validate_config_service_reference_not_found() {
    let config = Config {
      services: vec![],
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = MockListenerProps;
    validate_config(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert!(matches!(&errors[0], ConfigError::NotFound { .. }));
  }

  #[test]
  fn test_validate_config_invalid_listener_address() {
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["invalid:address".to_string()],
        ..Default::default()
      }],
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = MockListenerProps;
    validate_config(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(
      errors
        .iter()
        .any(|e| matches!(e, ConfigError::InvalidAddress { .. }))
    );
  }

  #[test]
  fn test_validate_config_https_without_tls() {
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "https_main".to_string(),
        kind: "https".to_string(),
        addresses: vec!["127.0.0.1:8443".to_string()],
        ..Default::default()
      }],
      servers: vec![Server {
        name: "https_server".to_string(),
        listeners: vec!["https_main".to_string()],
        service: "".to_string(),
        tls: None,
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = MockListenerProps;
    validate_config(&config, &mut collector, &lm);
    assert!(
      !collector.has_errors(),
      "HTTPS listener without TLS should not produce errors: {:?}",
      collector.errors()
    );
  }
}
