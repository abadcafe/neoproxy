use super::validate::*;
use crate::config::listener::{ListenerPropertyValues, TransportLayer};
use crate::config::{
  Config, ConfigError, ConfigErrorCollector, ListenerConfig,
  ListenerPropertiesProvider, Server, Service,
};

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
