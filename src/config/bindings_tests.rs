use super::listener_validation_test_support::MockListenerProps;
use super::{Config, ConfigErrorCollector};

#[test]
fn test_validate_rejects_independent_listeners_sharing_a_socket() {
  let config = Config::parse_str(
    r#"
listeners:
- {name: first, kind: http, addresses: ["127.0.0.1:8080"]}
- {name: second, kind: http, addresses: ["127.0.0.1:8080"]}
"#,
  )
  .unwrap();
  let mut errors = ConfigErrorCollector::new();
  config.validate(&mut errors, &MockListenerProps);
  assert!(errors.has_errors());
}

#[test]
fn test_validate_rejects_wildcard_address_overlap() {
  let config = Config::parse_str(
    r#"
listeners:
- {name: first, kind: http, addresses: ["0.0.0.0:8080"]}
- {name: second, kind: http, addresses: ["127.0.0.1:8080"]}
"#,
  )
  .unwrap();
  let mut errors = ConfigErrorCollector::new();
  config.validate(&mut errors, &MockListenerProps);
  assert!(errors.has_errors());
}
