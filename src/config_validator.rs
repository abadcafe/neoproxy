use std::process;

/// Configuration error kind
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigErrorKind {
  /// File read failed
  FileRead,
  /// YAML parsing failed
  YamlParse,
  /// Missing field
  MissingField,
  /// Invalid field format
  InvalidFormat,
  /// Reference not found
  NotFound,
  /// Type mismatch
  TypeMismatch,
  /// Address parsing failed
  InvalidAddress,
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

/// Get expected format string based on location context
///
/// Returns 'plugin_name.service_name' for service contexts
/// and 'plugin_name.listener_name' for listener contexts
fn get_expected_format(location: &str) -> &'static str {
  if location.contains("listeners") {
    "'plugin_name.listener_name'"
  } else {
    "'plugin_name.service_name'"
  }
}

/// Parse kind string into (plugin_name, item_name)
///
/// # Arguments
/// * `kind` - Kind string like "echo.echo" or "hyper.hyper"
/// * `location` - Error location context for error reporting
///
/// # Returns
/// * `Ok((plugin, name))` - Successfully parsed
/// * `Err(ConfigError)` - Invalid format
pub fn parse_kind<'a>(
  kind: &'a str,
  location: &str,
) -> Result<(&'a str, &'a str), ConfigError> {
  let expected_format = get_expected_format(location);

  // Count dots to reject multiple dots
  let dot_count = kind.matches('.').count();
  if dot_count != 1 {
    return Err(ConfigError {
      location: location.to_string(),
      message: format!(
        "invalid format '{}', expected {}",
        kind, expected_format
      ),
      kind: ConfigErrorKind::InvalidFormat,
    });
  }

  let mut parts = kind.splitn(2, '.');

  let plugin_name = parts.next().unwrap_or("");
  let item_name = parts.next().unwrap_or("");

  if plugin_name.is_empty() || item_name.is_empty() {
    return Err(ConfigError {
      location: location.to_string(),
      message: format!(
        "invalid format '{}', expected {}",
        kind, expected_format
      ),
      kind: ConfigErrorKind::InvalidFormat,
    });
  }

  Ok((plugin_name, item_name))
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
    collector.add("loc1", "msg1", ConfigErrorKind::MissingField);
    collector.add("loc2", "msg2", ConfigErrorKind::InvalidFormat);

    let errors = collector.errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].location, "loc1");
    assert_eq!(errors[1].location, "loc2");
  }

  #[test]
  fn test_parse_kind_valid() {
    let result = parse_kind("echo.echo", "services[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "echo");
    assert_eq!(name, "echo");
  }

  #[test]
  fn test_parse_kind_valid_different_names() {
    let result =
      parse_kind("hyper.hyper", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "hyper");
    assert_eq!(name, "hyper");
  }

  #[test]
  fn test_parse_kind_valid_with_underscore() {
    let result =
      parse_kind("connect_tcp.connect_tcp", "services[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "connect_tcp");
    assert_eq!(name, "connect_tcp");
  }

  #[test]
  fn test_parse_kind_missing_dot() {
    let result = parse_kind("echo", "services[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.location, "services[0].kind");
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("invalid format"));
    assert!(error.message.contains("service_name"));
  }

  #[test]
  fn test_parse_kind_missing_dot_listener_context() {
    let result = parse_kind("hyper", "servers[0].listeners[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.location, "servers[0].listeners[0].kind");
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("invalid format"));
    assert!(error.message.contains("listener_name"));
  }

  #[test]
  fn test_parse_kind_multiple_dots() {
    let result = parse_kind("echo.echo.echo", "services[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.location, "services[0].kind");
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("service_name"));
  }

  #[test]
  fn test_parse_kind_multiple_dots_listener_context() {
    let result =
      parse_kind("hyper.hyper.hyper", "servers[0].listeners[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.location, "servers[0].listeners[0].kind");
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("listener_name"));
  }

  #[test]
  fn test_parse_kind_empty_plugin() {
    let result = parse_kind(".echo", "services[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("service_name"));
  }

  #[test]
  fn test_parse_kind_empty_plugin_listener_context() {
    let result = parse_kind(".hyper", "servers[0].listeners[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("listener_name"));
  }

  #[test]
  fn test_parse_kind_empty_item() {
    let result = parse_kind("echo.", "services[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("service_name"));
  }

  #[test]
  fn test_parse_kind_empty_item_listener_context() {
    let result = parse_kind("hyper.", "servers[0].listeners[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("listener_name"));
  }

  #[test]
  fn test_parse_kind_empty_string() {
    let result = parse_kind("", "services[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("service_name"));
  }

  #[test]
  fn test_parse_kind_only_dot() {
    let result = parse_kind(".", "services[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("service_name"));
  }

  #[test]
  fn test_get_expected_format_service_context() {
    assert_eq!(
      get_expected_format("services[0].kind"),
      "'plugin_name.service_name'"
    );
    assert_eq!(
      get_expected_format("services[5].kind"),
      "'plugin_name.service_name'"
    );
  }

  #[test]
  fn test_get_expected_format_listener_context() {
    assert_eq!(
      get_expected_format("servers[0].listeners[0].kind"),
      "'plugin_name.listener_name'"
    );
    assert_eq!(
      get_expected_format("listeners[0].kind"),
      "'plugin_name.listener_name'"
    );
  }

  #[test]
  fn test_get_expected_format_default_context() {
    // Unknown contexts default to service_name
    assert_eq!(
      get_expected_format("unknown.kind"),
      "'plugin_name.service_name'"
    );
    assert_eq!(
      get_expected_format("custom.location"),
      "'plugin_name.service_name'"
    );
  }

  #[test]
  fn test_parse_kind_error_location_preserved() {
    let result = parse_kind("invalid", "custom.location.path");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.location, "custom.location.path");
  }

  #[test]
  fn test_parse_kind_valid_location_preserved() {
    let result = parse_kind("plugin.service", "test.location");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "plugin");
    assert_eq!(name, "service");
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
    collector.add("loc3", "msg3", ConfigErrorKind::MissingField);
    collector.add("loc4", "msg4", ConfigErrorKind::InvalidFormat);
    collector.add("loc5", "msg5", ConfigErrorKind::NotFound);
    collector.add("loc6", "msg6", ConfigErrorKind::TypeMismatch);
    collector.add("loc7", "msg7", ConfigErrorKind::InvalidAddress);

    assert_eq!(collector.errors().len(), 7);
    assert!(collector.has_errors());

    assert_eq!(collector.errors()[0].kind, ConfigErrorKind::FileRead);
    assert_eq!(collector.errors()[1].kind, ConfigErrorKind::YamlParse);
    assert_eq!(
      collector.errors()[2].kind,
      ConfigErrorKind::MissingField
    );
    assert_eq!(
      collector.errors()[3].kind,
      ConfigErrorKind::InvalidFormat
    );
    assert_eq!(collector.errors()[4].kind, ConfigErrorKind::NotFound);
    assert_eq!(
      collector.errors()[5].kind,
      ConfigErrorKind::TypeMismatch
    );
    assert_eq!(
      collector.errors()[6].kind,
      ConfigErrorKind::InvalidAddress
    );
  }
}
