//! Configuration error types.

use std::process;

/// Configuration error kind
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigErrorKind {
  /// File read failed
  FileRead,
  /// YAML parsing failed
  YamlParse,
  /// Invalid field format
  InvalidFormat,
  /// Reference not found
  NotFound,
  /// Address parsing failed
  InvalidAddress,
  /// Address conflict between listeners
  AddressConflict,
}

/// Configuration validation error
#[derive(Debug, Clone)]
pub struct ConfigError {
  /// Error location (e.g. "services[0].kind")
  pub location: String,
  /// Error message
  pub message: String,
  /// Error kind
  pub kind: ConfigErrorKind,
}

impl std::fmt::Display for ConfigError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}: {}", self.location, self.message)
  }
}

impl std::error::Error for ConfigError {}

/// Error collector for configuration validation
pub struct ConfigErrorCollector {
  errors: Vec<ConfigError>,
}

impl ConfigErrorCollector {
  /// Create a new error collector
  pub fn new() -> Self {
    Self { errors: Vec::new() }
  }

  /// Add an error
  pub fn add(
    &mut self,
    location: impl Into<String>,
    message: impl Into<String>,
    kind: ConfigErrorKind,
  ) {
    self.errors.push(ConfigError {
      location: location.into(),
      message: message.into(),
      kind,
    });
  }

  /// Check if there are any errors
  pub fn has_errors(&self) -> bool {
    !self.errors.is_empty()
  }

  /// Get all errors
  pub fn errors(&self) -> &[ConfigError] {
    &self.errors
  }

  /// Print error report and exit with code 1
  pub fn report_and_exit(&self) -> ! {
    if self.errors.is_empty() {
      eprintln!("No configuration errors found.");
      process::exit(0);
    }

    eprintln!("Configuration errors:");
    for error in &self.errors {
      eprintln!("  {}: {}", error.location, error.message);
    }

    eprintln!();
    let error_count = self.errors.len();
    let error_word = if error_count == 1 { "error" } else { "errors" };
    eprintln!(
      "{} {} found. Please fix the configuration file.",
      error_count, error_word
    );
    process::exit(1);
  }
}

impl Default for ConfigErrorCollector {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_config_error_display() {
    let error = ConfigError {
      location: "services[0].kind".to_string(),
      message: "invalid format".to_string(),
      kind: ConfigErrorKind::InvalidFormat,
    };
    assert_eq!(
      format!("{}", error),
      "services[0].kind: invalid format"
    );
  }

  #[test]
  fn test_config_error_kind_equality() {
    assert_eq!(ConfigErrorKind::FileRead, ConfigErrorKind::FileRead);
    assert_eq!(
      ConfigErrorKind::InvalidFormat,
      ConfigErrorKind::InvalidFormat
    );
    assert_ne!(ConfigErrorKind::FileRead, ConfigErrorKind::YamlParse);
  }

  #[test]
  fn test_error_collector_new() {
    let collector = ConfigErrorCollector::new();
    assert!(!collector.has_errors());
    assert!(collector.errors().is_empty());
  }

  #[test]
  fn test_error_collector_default() {
    let collector = ConfigErrorCollector::default();
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_error_collector_add_single_error() {
    let mut collector = ConfigErrorCollector::new();
    collector.add(
      "services[0].kind",
      "plugin 'unknown_plugin' not found",
      ConfigErrorKind::NotFound,
    );

    assert!(collector.has_errors());
    assert_eq!(collector.errors().len(), 1);

    let error = &collector.errors()[0];
    assert_eq!(error.location, "services[0].kind");
    assert_eq!(error.message, "plugin 'unknown_plugin' not found");
    assert_eq!(error.kind, ConfigErrorKind::NotFound);
  }

  #[test]
  fn test_error_collector_add_multiple_errors() {
    let mut collector = ConfigErrorCollector::new();

    collector.add(
      "services[0].kind",
      "plugin 'unknown_plugin' not found",
      ConfigErrorKind::NotFound,
    );
    collector.add(
      "servers[0].listeners[0].kind",
      "listener builder 'http' not found",
      ConfigErrorKind::NotFound,
    );

    assert!(collector.has_errors());
    assert_eq!(collector.errors().len(), 2);
  }

  #[test]
  fn test_error_collector_add_with_string_types() {
    let mut collector = ConfigErrorCollector::new();
    let location = String::from("services[0].kind");
    let message = String::from("error message");

    collector.add(location, message, ConfigErrorKind::InvalidFormat);

    assert!(collector.has_errors());
    assert_eq!(collector.errors()[0].location, "services[0].kind");
    assert_eq!(collector.errors()[0].message, "error message");
  }

  #[test]
  fn test_error_collector_errors_slice() {
    let mut collector = ConfigErrorCollector::new();
    collector.add("loc1", "msg1", ConfigErrorKind::InvalidFormat);
    collector.add("loc2", "msg2", ConfigErrorKind::InvalidFormat);

    let errors = collector.errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].location, "loc1");
    assert_eq!(errors[1].location, "loc2");
  }

  #[test]
  fn test_config_error_is_error() {
    fn assert_error<E: std::error::Error>() {}
    assert_error::<ConfigError>();
  }

  #[test]
  fn test_config_error_debug() {
    let error = ConfigError {
      location: "test".to_string(),
      message: "test message".to_string(),
      kind: ConfigErrorKind::InvalidFormat,
    };
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("ConfigError"));
    assert!(debug_str.contains("test"));
  }

  #[test]
  fn test_config_error_kind_debug() {
    let kind = ConfigErrorKind::InvalidFormat;
    let debug_str = format!("{:?}", kind);
    assert!(debug_str.contains("InvalidFormat"));
  }

  #[test]
  fn test_error_collector_all_error_kinds() {
    let mut collector = ConfigErrorCollector::new();

    collector.add("loc1", "msg1", ConfigErrorKind::FileRead);
    collector.add("loc2", "msg2", ConfigErrorKind::YamlParse);
    collector.add("loc3", "msg3", ConfigErrorKind::InvalidFormat);
    collector.add("loc4", "msg4", ConfigErrorKind::NotFound);
    collector.add("loc5", "msg5", ConfigErrorKind::InvalidAddress);
    collector.add("loc6", "msg6", ConfigErrorKind::AddressConflict);

    assert_eq!(collector.errors().len(), 6);
    assert!(collector.has_errors());

    assert_eq!(collector.errors()[0].kind, ConfigErrorKind::FileRead);
    assert_eq!(collector.errors()[1].kind, ConfigErrorKind::YamlParse);
    assert_eq!(
      collector.errors()[2].kind,
      ConfigErrorKind::InvalidFormat
    );
    assert_eq!(collector.errors()[3].kind, ConfigErrorKind::NotFound);
    assert_eq!(
      collector.errors()[4].kind,
      ConfigErrorKind::InvalidAddress
    );
    assert_eq!(
      collector.errors()[5].kind,
      ConfigErrorKind::AddressConflict
    );
  }
}
