use super::service::Service;
use super::{Config, ConfigErrorCollector};
use crate::config::listener_validation_test_support::MockListenerProps;

#[test]
fn test_service_default() {
  let service = Service::default();

  assert!(service.name().is_empty());
  assert!(service.plugin_name().is_empty());
  assert!(service.kind().is_empty());
  assert!(service.layers().is_empty());
}

#[test]
fn test_parse_str_service_kind_split_into_parts() {
  let config = Config::parse_str(
    r#"
services:
- name: my_svc
  kind: connect_tcp.connect_tcp
  layers: []
servers: []
"#,
  )
  .unwrap();

  let service = &config.services()[0];
  assert_eq!(service.plugin_name(), "connect_tcp");
  assert_eq!(service.kind(), "connect_tcp");
  assert_eq!(service.name(), "my_svc");
  assert!(service.layers().is_empty());
}

#[test]
fn test_parse_str_service_kind_invalid() {
  let result = Config::parse_str(
    r#"
services:
- name: my_svc
  kind: nodot
  layers: []
servers: []
"#,
  );

  assert!(result.is_err());
}

#[test]
fn test_parse_str_service_layers_split_into_parts() {
  let config = Config::parse_str(
    r#"
services:
- name: my_svc
  kind: echo.echo
  layers:
  - kind: auth.basic_auth
  - kind: access_log.file
servers: []
"#,
  )
  .unwrap();

  let service = &config.services()[0];
  assert_eq!(service.layers().len(), 2);
  assert_eq!(service.layers()[0].plugin_name(), "auth");
  assert_eq!(service.layers()[0].kind(), "basic_auth");
  assert_eq!(service.layers()[1].plugin_name(), "access_log");
  assert_eq!(service.layers()[1].kind(), "file");
}

#[test]
fn test_validate_missing_service_reference_rejected() {
  let config = Config::parse_str(
    r#"
services: []
servers:
- name: server1
  service: nonexistent
  listeners: []
"#,
  )
  .unwrap();
  let mut collector = ConfigErrorCollector::new();

  config.validate(&mut collector, &MockListenerProps);

  assert!(collector.has_errors());
}

#[test]
fn test_validate_existing_service_reference_allowed() {
  let config = Config::parse_str(
    r#"
services:
- name: echo
  kind: echo.echo
  layers: []
servers:
- name: server1
  service: echo
  listeners: []
"#,
  )
  .unwrap();
  let mut collector = ConfigErrorCollector::new();

  config.validate(&mut collector, &MockListenerProps);

  assert!(
    !collector.has_errors(),
    "existing service reference should pass: {:?}",
    collector.errors()
  );
}

#[test]
fn test_validate_empty_service_reference_allowed() {
  let config = Config::parse_str(
    r#"
services: []
servers:
- name: server1
  service: ""
  listeners: []
"#,
  )
  .unwrap();
  let mut collector = ConfigErrorCollector::new();

  config.validate(&mut collector, &MockListenerProps);

  assert!(
    !collector.has_errors(),
    "empty service name should be allowed: {:?}",
    collector.errors()
  );
}

#[test]
fn test_parse_str_preserves_flat_service_and_layer_parameters() {
  let config = Config::parse_str(
    "services:\n- name: proxy\n  kind: upstream.upstream\n  upstream: \
     direct\n  layers:\n  - kind: auth.basic_auth\n    users:\n    - \
     username: alice\n      password: secret",
  )
  .unwrap();
  let service = &config.services()[0];
  assert_eq!(service.args()["upstream"].as_str(), Some("direct"));
  assert!(service.args().get("layers").is_none());
  assert_eq!(
    service.layers()[0].args()["users"][0]["username"].as_str(),
    Some("alice")
  );
}
