//! Configuration error types.

use std::process;

/// Configuration validation error.
///
/// Each variant represents a distinct class of configuration error.
/// Use pattern matching to inspect errors instead of string comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigError {
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
  /// Hostname conflict between servers.
  HostnameConflict { location: String, message: String },
}

impl ConfigError {
  pub(crate) fn location(&self) -> &str {
    match self {
      Self::FileRead { location, .. }
      | Self::InvalidFormat { location, .. }
      | Self::NotFound { location, .. }
      | Self::InvalidAddress { location, .. }
      | Self::AddressConflict { location, .. }
      | Self::HostnameConflict { location, .. } => location,
    }
  }

  pub(crate) fn message(&self) -> &str {
    match self {
      Self::FileRead { message, .. }
      | Self::InvalidFormat { message, .. }
      | Self::NotFound { message, .. }
      | Self::InvalidAddress { message, .. }
      | Self::AddressConflict { message, .. }
      | Self::HostnameConflict { message, .. } => message,
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
pub(crate) struct ConfigErrorCollector {
  errors: Vec<ConfigError>,
}

impl ConfigErrorCollector {
  /// Create a new error collector
  pub(crate) fn new() -> Self {
    Self { errors: Vec::new() }
  }

  /// Add an error
  pub(crate) fn add(&mut self, error: ConfigError) {
    self.errors.push(error);
  }

  /// Check if there are any errors
  pub(crate) fn has_errors(&self) -> bool {
    !self.errors.is_empty()
  }

  /// Get collected errors for callers that need structured reporting.
  pub(crate) fn errors(&self) -> &[ConfigError] {
    &self.errors
  }

  /// Print error report and exit with code 1
  pub(crate) fn report_and_exit(&self) -> ! {
    if self.errors().is_empty() {
      eprintln!("No configuration errors found.");
      process::exit(0);
    }

    eprintln!("Configuration errors:");
    for error in self.errors() {
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
