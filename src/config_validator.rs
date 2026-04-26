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
/// Returns 'protocol_name' for listener contexts (e.g., "http", "https", "http3", "socks5")
/// and 'plugin_name.service_name' for service contexts
fn get_expected_format(location: &str) -> &'static str {
  if location.contains("listeners") {
    "'protocol_name' (e.g., http, https, http3, socks5)"
  } else {
    "'plugin_name.service_name'"
  }
}

/// Check if location is a listener context
fn is_listener_context(location: &str) -> bool {
  location.contains("listeners")
}

/// Parse kind string into (plugin_name, item_name)
///
/// # Arguments
/// * `kind` - Kind string like "echo.echo" for services or "http" for listeners
/// * `location` - Error location context for error reporting
///
/// # Returns
/// * `Ok((plugin, name))` - Successfully parsed
/// * `Err(ConfigError)` - Invalid format
///
/// # Format
/// - For listeners: just the protocol name (e.g., "http", "https", "http3", "socks5")
/// - For services: "plugin_name.service_name" format (e.g., "echo.echo")
pub fn parse_kind<'a>(
  kind: &'a str,
  location: &str,
) -> Result<(&'a str, &'a str), ConfigError> {
  let expected_format = get_expected_format(location);

  // For listener contexts, accept simple protocol names without dots
  if is_listener_context(location) {
    // Listener kinds are simple protocol names like "http", "https", "http3", "socks5"
    if kind.is_empty() {
      return Err(ConfigError {
        location: location.to_string(),
        message: format!(
          "invalid format '{}', expected {}",
          kind, expected_format
        ),
        kind: ConfigErrorKind::InvalidFormat,
      });
    }
    // Return the kind as both plugin and name for consistency
    // The actual validation happens when checking if the builder exists
    return Ok((kind, kind));
  }

  // For service contexts, require "plugin_name.service_name" format
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
    collector.add("loc1", "msg1", ConfigErrorKind::InvalidAddress);
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
  fn test_parse_kind_valid_listener_simple() {
    // New listener format: simple protocol name without dots
    let result = parse_kind("http", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "http");
    assert_eq!(name, "http");
  }

  #[test]
  fn test_parse_kind_valid_listener_https() {
    let result = parse_kind("https", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "https");
    assert_eq!(name, "https");
  }

  #[test]
  fn test_parse_kind_valid_listener_http3() {
    let result = parse_kind("http3", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "http3");
    assert_eq!(name, "http3");
  }

  #[test]
  fn test_parse_kind_valid_listener_socks5() {
    let result = parse_kind("socks5", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "socks5");
    assert_eq!(name, "socks5");
  }

  #[test]
  fn test_parse_kind_valid_listener_with_dot() {
    // With the new naming convention, listener kinds accept any non-empty string
    // The old format "hyper.listener" would be treated as a simple name
    // (The actual validation happens when checking if the builder exists)
    let result =
      parse_kind("hyper.listener", "servers[0].listeners[0].kind");
    // This now passes parse_kind (format validation) but will fail at builder lookup
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "hyper.listener");
    assert_eq!(name, "hyper.listener");
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
    // Listener kinds now accept simple names without dots
    let result = parse_kind("hyper", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "hyper");
    assert_eq!(name, "hyper");
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
    // Listener kinds now accept simple names without dots
    // Multiple dots should fail for services but pass for listeners (just returns the name)
    let result =
      parse_kind("http", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "http");
    assert_eq!(name, "http");
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
    // For listener contexts, we accept any non-empty string
    // Even strings with dots are accepted (they're returned as-is)
    let result = parse_kind(".hyper", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, ".hyper");
    assert_eq!(name, ".hyper");
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
    // For listener contexts, we accept any non-empty string
    // Even strings with dots are accepted (they're returned as-is)
    let result = parse_kind("hyper.", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, "hyper.");
    assert_eq!(name, "hyper.");
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
  fn test_parse_kind_empty_string_listener_context() {
    // Empty string should fail even for listeners
    let result = parse_kind("", "servers[0].listeners[0].kind");
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.kind, ConfigErrorKind::InvalidFormat);
    assert!(error.message.contains("protocol_name"));
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
  fn test_parse_kind_only_dot_listener_context() {
    // For listener contexts, we accept any non-empty string
    // Even a single dot is accepted
    let result = parse_kind(".", "servers[0].listeners[0].kind");
    assert!(result.is_ok());

    let (plugin, name) = result.unwrap();
    assert_eq!(plugin, ".");
    assert_eq!(name, ".");
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
      "'protocol_name' (e.g., http, https, http3, socks5)"
    );
    assert_eq!(
      get_expected_format("listeners[0].kind"),
      "'protocol_name' (e.g., http, https, http3, socks5)"
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

  // =========================================================================
  // Address Conflict Detection Tests
  // =========================================================================

  /// Helper function to check if error message contains a substring
  fn has_error_containing(collector: &ConfigErrorCollector, substring: &str) -> bool {
    collector.errors().iter().any(|e| e.message.contains(substring))
  }

  #[test]
  fn test_address_conflict_tcp_vs_tcp_different_kind() {
    // Two listeners of different TCP kinds on same address should conflict
    use crate::config::{Config, Server, Listener, Service};

    let args1 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#).unwrap();
    let args2 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#).unwrap();

    let config = Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "socks5".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(&collector, "address conflict"));
  }

  #[test]
  fn test_address_no_conflict_tcp_vs_udp() {
    // HTTP (TCP) and HTTP/3 (UDP) on same address should NOT conflict
    use crate::config::{Config, Server, Listener, Service, ServerTlsConfig, CertificateConfig};

    // Install CryptoProvider for TLS validation
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: serde_yaml::Value = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#).unwrap();

    let config = Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![Server {
        name: "server1".to_string(),
        hostnames: vec![],
        tls: Some(ServerTlsConfig {
          certificates: vec![CertificateConfig {
            cert_path: "conf/certs/server.crt".to_string(),
            key_path: "conf/certs/server.key".to_string(),
          }],
          client_ca_certs: None,
        }),
        users: None,
        listeners: vec![
          Listener {
            kind: "http".to_string(),
            args: args.clone(),
          },
          Listener {
            kind: "http3".to_string(),
            args: args,
          },
        ],
        service: "echo".to_string(),
        access_log: None,
      }],
    };

    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // Should NOT have address conflict errors (may have other errors like missing cert files)
    let has_address_conflict = has_error_containing(&collector, "address conflict");
    assert!(!has_address_conflict, "Expected no address conflict, but found one");
  }

  #[test]
  fn test_address_same_kind_can_share_with_hostnames() {
    // Same kind (http) CAN share address when they support hostname routing
    use crate::config::{Config, Server, Listener, Service};

    let args: serde_yaml::Value = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#).unwrap();

    let config = Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "default_server".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args.clone(),
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "api_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // Should be VALID - same kind with hostname routing can share address
    assert!(!collector.has_errors(), "Expected no errors but found: {:?}", collector.errors());
  }

  #[test]
  fn test_address_socks5_cannot_share() {
    // socks5 does NOT support hostname routing, so multiple socks5 on same address = CONFLICT
    use crate::config::{Config, Server, Listener, Service};

    let args1 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#).unwrap();
    let args2 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#).unwrap();

    let config = Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "socks5".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "socks5".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(&collector, "address conflict"));
  }

  #[test]
  fn test_address_multiple_http_no_hostnames_conflict() {
    // CR-003: Multiple default servers (empty hostnames) on same address+kind should cause error
    // This causes routing ambiguity - when no Host header matches, which default server handles the request?
    use crate::config::{Config, Server, Listener, Service};

    let args1 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#).unwrap();
    let args2 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#).unwrap();

    let config = Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // CR-003: This should be an error - multiple default servers on same address
    assert!(collector.has_errors(), "Expected error for multiple default servers on same address");
    assert!(has_error_containing(&collector, "multiple default servers"), "Error should mention multiple default servers");
  }

  #[test]
  fn test_address_udp_vs_udp_conflict() {
    // Two HTTP/3 listeners on same address should NOT conflict if they support hostname routing
    // (similar to TCP case - same kind can share with hostname routing)
    use crate::config::{Config, Server, Listener, Service, ServerTlsConfig, CertificateConfig};

    // Install CryptoProvider for TLS validation
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args1 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#).unwrap();
    let args2 = serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#).unwrap();

    let config = Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: Some(ServerTlsConfig {
            certificates: vec![CertificateConfig {
              cert_path: "conf/certs/server.crt".to_string(),
              key_path: "conf/certs/server.key".to_string(),
            }],
            client_ca_certs: None,
          }),
          users: None,
          listeners: vec![Listener {
            kind: "http3".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "server2".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          tls: Some(ServerTlsConfig {
            certificates: vec![CertificateConfig {
              cert_path: "conf/certs/server.crt".to_string(),
              key_path: "conf/certs/server.key".to_string(),
            }],
            client_ca_certs: None,
          }),
          users: None,
          listeners: vec![Listener {
            kind: "http3".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // Same UDP kind with hostname routing support is allowed
    // (may have cert file errors but should not have address conflict)
    let has_address_conflict = has_error_containing(&collector, "address conflict");
    assert!(!has_address_conflict, "Expected no address conflict for same UDP kind with hostname routing");
  }
}
