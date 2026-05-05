//! Configuration error types.

use std::process;

/// Configuration validation error.
///
/// Each variant represents a distinct class of configuration error.
/// Use pattern matching to inspect errors instead of string comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
  /// File read failed.
  FileRead { location: String, message: String },
  /// Invalid field format.
  InvalidFormat { location: String, message: String },
  /// Reference not found.
  NotFound { location: String, message: String },
  /// Address parsing failed.
  InvalidAddress { location: String, message: String },
  /// Address conflict between listeners.
  AddressConflict { location: String, message: String },
}

impl ConfigError {
  pub fn location(&self) -> &str {
    match self {
      Self::FileRead { location, .. }
      | Self::InvalidFormat { location, .. }
      | Self::NotFound { location, .. }
      | Self::InvalidAddress { location, .. }
      | Self::AddressConflict { location, .. } => location,
    }
  }

  pub fn message(&self) -> &str {
    match self {
      Self::FileRead { message, .. }
      | Self::InvalidFormat { message, .. }
      | Self::NotFound { message, .. }
      | Self::InvalidAddress { message, .. }
      | Self::AddressConflict { message, .. } => message,
    }
  }
}

impl std::fmt::Display for ConfigError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}: {}", self.location(), self.message())
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
  pub fn add(&mut self, error: ConfigError) {
    self.errors.push(error);
  }

  /// Check if there are any errors
  pub fn has_errors(&self) -> bool {
    !self.errors.is_empty()
  }

  /// Get all errors (test-only: production code uses
  /// has_errors/report_and_exit)
  #[cfg(test)]
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
      eprintln!("  {}", error);
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
    let error = ConfigError::InvalidFormat {
      location: "services[0].kind".to_string(),
      message: "invalid format".to_string(),
    };
    assert_eq!(
      format!("{}", error),
      "services[0].kind: invalid format"
    );
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
      collector.errors[0],
      ConfigError::NotFound { .. }
    ));
    assert_eq!(collector.errors[0].location(), "services[0].kind");
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
    assert_eq!(collector.errors.len(), 2);
  }
}
