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
fn test_validate_hostname_conflicts_socks5_multiple_servers() {
  let collector = validate_yaml(
    r#"
listeners:
- name: socks5_main
  kind: socks5
  addresses: ["127.0.0.1:1080"]
servers:
- name: server_a
  listeners: ["socks5_main"]
  service: ""
- name: server_b
  listeners: ["socks5_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::InvalidFormat { .. })
  }));
}

#[test]
fn test_validate_hostname_conflicts_socks5_single_server_ok() {
  let collector = validate_yaml(
    r#"
listeners:
- name: socks5_main
  kind: socks5
  addresses: ["127.0.0.1:1080"]
servers:
- name: server_a
  listeners: ["socks5_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_conflicts_http_hostname_overlap() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: server_a
  hostnames: ["api.example.com"]
  listeners: ["http_main"]
  service: ""
- name: server_b
  hostnames: ["api.example.com"]
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::HostnameConflict { .. })
  }));
}

#[test]
fn test_validate_hostname_conflicts_http_multiple_defaults() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: default_a
  listeners: ["http_main"]
  service: ""
- name: default_b
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::HostnameConflict { .. })
  }));
}

#[test]
fn test_validate_hostname_conflicts_http_no_overlap_ok() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: server_a
  hostnames: ["api.example.com"]
  listeners: ["http_main"]
  service: ""
- name: server_b
  hostnames: ["web.example.com"]
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_conflicts_single_server_skipped() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: server_a
  hostnames: ["api.example.com"]
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}
