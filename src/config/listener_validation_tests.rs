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
fn test_validate_listener_addresses_valid_address() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_listener_addresses_invalid_address() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["invalid:address"]
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::InvalidAddress { .. })
  }));
}

#[test]
fn test_validate_listener_addresses_multiple_invalid_addresses() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["invalid1", "127.0.0.1:8080", "invalid2"]
"#,
  );

  let count = collector
    .errors()
    .iter()
    .filter(|e| matches!(e, ConfigError::InvalidAddress { .. }))
    .count();
  assert_eq!(count, 2);
}

#[test]
fn test_validate_listener_addresses_empty_array() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: []
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(
      e,
      ConfigError::InvalidAddress { message, .. }
        if message == "addresses list cannot be empty"
    )
  }));
}

#[test]
fn test_validate_hostname_empty_is_error() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: api
  hostnames: [""]
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(
      e,
      ConfigError::InvalidFormat { message, .. }
        if message == "hostname cannot be empty"
    )
  }));
}

#[test]
fn test_validate_hostname_exact_single_label_and_wildcard_are_valid() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: api
  hostnames: ["api.example.com", "localhost", "*.sub.example.com"]
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_invalid_wildcards_are_errors() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: api
  hostnames: ["*", "*example.com"]
  listeners: ["http_main"]
  service: ""
"#,
  );

  let count = collector
    .errors()
    .iter()
    .filter(|e| matches!(e, ConfigError::InvalidFormat { .. }))
    .count();
  assert_eq!(count, 2);
}

#[test]
fn test_validate_hostname_routing_socks5_with_hostnames_error() {
  let collector = validate_yaml(
    r#"
listeners:
- name: socks5_main
  kind: socks5
  addresses: ["127.0.0.1:1080"]
servers:
- name: socks_server
  hostnames: ["api.example.com"]
  listeners: ["socks5_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::InvalidFormat { .. })
  }));
}

#[test]
fn test_validate_hostname_routing_socks5_empty_hostnames_ok() {
  let collector = validate_yaml(
    r#"
listeners:
- name: socks5_main
  kind: socks5
  addresses: ["127.0.0.1:1080"]
servers:
- name: socks_server
  hostnames: []
  listeners: ["socks5_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_routing_http_with_hostnames_ok() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: http_server
  hostnames: ["api.example.com"]
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_hostname_routing_mixed_listeners_reports_only_unsupported_listener()
 {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
- name: socks5_main
  kind: socks5
  addresses: ["127.0.0.1:1080"]
servers:
- name: mixed
  hostnames: ["api.example.com"]
  listeners: ["http_main", "socks5_main"]
  service: ""
"#,
  );

  let errors: Vec<_> = collector
    .errors()
    .iter()
    .filter(|e| matches!(e, ConfigError::InvalidFormat { .. }))
    .collect();
  assert_eq!(errors.len(), 1);
  assert!(errors[0].location().contains("listeners[1]"));
}

#[test]
fn test_validate_hostname_routing_unknown_listener_kind_is_skipped() {
  let collector = validate_yaml(
    r#"
listeners:
- name: unknown_main
  kind: unknown_kind
  addresses: ["127.0.0.1:9999"]
servers:
- name: unknown_server
  hostnames: ["api.example.com"]
  listeners: ["unknown_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_address_conflicts_tcp_same_address_different_kind() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
- name: socks5_main
  kind: socks5
  addresses: ["127.0.0.1:8080"]
servers:
- name: server1
  listeners: ["http_main"]
  service: ""
- name: server2
  listeners: ["socks5_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::AddressConflict { .. })
  }));
}

#[test]
fn test_validate_address_conflicts_same_kind_hostnames_can_share_address()
 {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: default_server
  listeners: ["http_main"]
  service: ""
- name: api_server
  hostnames: ["api.example.com"]
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_address_conflicts_multiple_default_servers_conflict() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: server1
  listeners: ["http_main"]
  service: ""
- name: server2
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::HostnameConflict { .. })
  }));
}

#[test]
fn test_validate_address_conflicts_duplicate_hostname_conflict() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: server_a
  hostnames: ["API.EXAMPLE.COM"]
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
fn test_validate_address_conflicts_distinct_hostnames_are_allowed() {
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

  assert!(!has_error(&collector, |e| {
    matches!(e, ConfigError::AddressConflict { .. })
  }));
  assert!(!has_error(&collector, |e| {
    matches!(e, ConfigError::HostnameConflict { .. })
  }));
}

#[test]
fn test_validate_listener_references_valid_reference() {
  let collector = validate_yaml(
    r#"
listeners:
- name: http_main
  kind: http
  addresses: ["127.0.0.1:8080"]
servers:
- name: server1
  listeners: ["http_main"]
  service: ""
"#,
  );

  assert!(!collector.has_errors(), "{:?}", collector.errors());
}

#[test]
fn test_validate_listener_references_missing_reference() {
  let collector = validate_yaml(
    r#"
servers:
- name: server1
  listeners: ["missing"]
  service: ""
"#,
  );

  assert!(has_error(&collector, |e| {
    matches!(e, ConfigError::NotFound { .. })
  }));
}
