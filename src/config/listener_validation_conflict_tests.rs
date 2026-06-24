use super::listener_validation::*;
use super::listener_validation_test_support::MockListenerProps;
use super::{ConfigError, ConfigErrorCollector};

// =========================================================================
// validate_hostname_conflicts Tests
// =========================================================================

#[test]
fn test_validate_hostname_conflicts_socks5_multiple_servers() {
  // Two servers referencing the same socks5 listener
  // (non-hostname-routing)
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "socks5_main".to_string(),
      kind: "socks5".to_string(),
      addresses: vec!["127.0.0.1:1080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server_a".to_string(),
        hostnames: vec![],
        listeners: vec!["socks5_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server_b".to_string(),
        hostnames: vec![],
        listeners: vec!["socks5_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::InvalidFormat { .. }
  ));
}

#[test]
fn test_validate_hostname_conflicts_socks5_single_server_ok() {
  // One server referencing socks5 listener is valid
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "socks5_main".to_string(),
      kind: "socks5".to_string(),
      addresses: vec!["127.0.0.1:1080".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "server_a".to_string(),
      hostnames: vec![],
      listeners: vec!["socks5_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_conflicts(&config, &mut collector, &lm);
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_conflicts_http_hostname_overlap() {
  // Two servers with overlapping hostnames on the same http listener
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server_a".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server_b".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::HostnameConflict { .. }
  ));
}

#[test]
fn test_validate_hostname_conflicts_http_multiple_defaults() {
  // Two default servers (empty hostnames) on the same http listener
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "default_a".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "default_b".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_conflicts(&config, &mut collector, &lm);
  assert!(collector.has_errors());
  assert!(matches!(
    &collector.errors()[0],
    ConfigError::HostnameConflict { .. }
  ));
}

#[test]
fn test_validate_hostname_conflicts_http_no_overlap_ok() {
  // Two servers with different hostnames on the same http listener is
  // valid
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![
      super::Server {
        name: "server_a".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
      super::Server {
        name: "server_b".to_string(),
        hostnames: vec!["web.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      },
    ],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_conflicts(&config, &mut collector, &lm);
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_conflicts_single_server_skipped() {
  // Single server per listener is always valid (no conflict possible)
  let config = super::Config {
    listeners: vec![super::ListenerConfig {
      name: "http_main".to_string(),
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      ..Default::default()
    }],
    servers: vec![super::Server {
      name: "server_a".to_string(),
      hostnames: vec!["api.example.com".to_string()],
      listeners: vec!["http_main".to_string()],
      service: "".to_string(),
      ..Default::default()
    }],
    ..Default::default()
  };
  let mut collector = ConfigErrorCollector::new();
  let lm = MockListenerProps;
  validate_hostname_conflicts(&config, &mut collector, &lm);
  assert!(!collector.has_errors(), "{:?}", collector.errors());
}
