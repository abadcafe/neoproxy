use super::listener_validation_test_support::MockListenerProps;
use super::{Config, ConfigError, ConfigErrorCollector};

fn validate_yaml(yaml: &str) -> ConfigErrorCollector {
  let config = Config::parse_str(yaml).unwrap();
  let mut collector = ConfigErrorCollector::new();
  config.validate(&mut collector, &MockListenerProps);
  collector
}

fn has_error(
  collector: &ConfigErrorCollector,
  discriminant: impl Fn(&ConfigError) -> bool,
) -> bool {
  collector.errors().iter().any(discriminant)
}

#[test]
fn test_validate_config_valid() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
services:
- name: echo
  kind: echo.echo
servers:
- name: server1
  listeners: ["http_main"]
  service: echo
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_config_empty() {
  let mut collector = ConfigErrorCollector::new();
  Config::default().validate(&mut collector, &MockListenerProps);

  assert!(!collector.has_errors());
}

#[test]
fn test_validate_config_server_threads_zero() {
  let collector = validate_yaml("server_threads: 0\n");

  assert!(has_error(&collector, |e| {
    matches!(
      e,
      ConfigError::InvalidFormat { location, .. }
        if location == "server_threads"
    )
  }));
}

#[test]
fn test_validate_config_service_reference_not_found() {
  let collector = validate_yaml(
    r#"
servers:
- name: test_server
  service: nonexistent
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::NotFound { .. })
  }));
}

#[test]
fn test_validate_config_invalid_listener_address() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["invalid:address"]
servers:
- name: test
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::InvalidAddress { .. })
  }));
}

#[test]
fn test_validate_config_https_without_tls() {
  let collector = validate_yaml(
    r#"
listeners:
- name: https_main
  kind: https
  addresses: ["127.0.0.1:8443"]
servers:
- name: https_server
  listeners: ["https_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}
