use super::error::*;

#[test]
fn test_config_error_display() {
  let error = ConfigError::InvalidFormat {
    location: "services[0].kind".to_string(),
    message: "invalid format".to_string(),
  };
  assert_eq!(format!("{}", error), "services[0].kind: invalid format");
}

#[test]
fn test_config_error_is_error() {
  fn assert_error<E: std::error::Error>() {}
  assert_error::<ConfigError>();
}

#[test]
fn test_config_error_debug() {
  let error = ConfigError::NotFound {
    location: "test".to_string(),
    message: "test message".to_string(),
  };
  let debug_str = format!("{:?}", error);
  assert!(debug_str.contains("NotFound"));
  assert!(debug_str.contains("test"));
}

#[test]
fn test_error_collector_new() {
  let collector = ConfigErrorCollector::new();
  assert!(!collector.has_errors());
}

#[test]
fn test_error_collector_default() {
  let collector = ConfigErrorCollector::default();
  assert!(!collector.has_errors());
}

#[test]
fn test_error_collector_add_single_error() {
  let mut collector = ConfigErrorCollector::new();
  collector.add(ConfigError::NotFound {
    location: "services[0].kind".into(),
    message: "plugin 'unknown_plugin' not found".into(),
  });

  assert!(collector.has_errors());
  assert!(matches!(
    collector.errors()[0],
    ConfigError::NotFound { .. }
  ));
  assert_eq!(collector.errors()[0].location(), "services[0].kind");
}

#[test]
fn test_error_collector_add_multiple_errors() {
  let mut collector = ConfigErrorCollector::new();
  collector.add(ConfigError::NotFound {
    location: "services[0].kind".into(),
    message: "plugin 'unknown_plugin' not found".into(),
  });
  collector.add(ConfigError::NotFound {
    location: "servers[0].listeners[0]".into(),
    message: "listener builder 'http' not found".into(),
  });

  assert!(collector.has_errors());
  assert_eq!(collector.errors().len(), 2);
}
