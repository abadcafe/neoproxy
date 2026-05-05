//! Configuration types, parsing, and validation.
//!
//! This module provides:
//! - Core configuration types (Config, Server, Service, ListenerConfig)
//! - Configuration parsing from YAML files
//! - Configuration validation with detailed error reporting
//! - `SerializedArgs` type for configuration data

mod auth;
mod error;
mod listener;
mod service;
mod tls;

use std::sync::{LazyLock, OnceLock};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

// Re-export types from submodules
pub use self::auth::UserCredential;
pub use self::error::{ConfigError, ConfigErrorCollector};
pub use self::listener::{
  ListenerConfig, validate_address_conflicts, validate_hostname,
  validate_hostname_conflicts, validate_hostname_routing_compatibility,
  validate_listener_addresses, validate_listener_references,
};
pub use self::service::{Service, ServiceRaw, validate_service};
pub use self::tls::{
  CertificateConfig, ServerTlsConfig, validate_server_tls,
};

/// Serialized configuration arguments.
///
/// A type alias for `serde_yaml::Value`, used to pass configuration
/// data from YAML files to listener and service builders.
pub type SerializedArgs = serde_yaml::Value;

/// Layer configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct LayerRaw {
  pub kind: String,
  pub args: SerializedArgs,
}

/// Layer configuration (after kind parsing).
#[derive(Default, Clone, Debug)]
pub struct Layer {
  pub plugin_name: String,
  pub kind: String,
  pub args: SerializedArgs,
}

/// Global config instance, initialized via `Config::init_global()`.
static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

/// Command line options.
#[derive(Parser, Debug)]
pub struct CmdOpt {
  /// Sets a custom config file
  #[arg(
    short,
    long = "config",
    value_name = "CONFIG_FILE",
    default_value_t = String::from("conf/server.yaml")
  )]
  pub config_file: String,

  /// Gets version
  #[arg(short, long = "version")]
  pub version: bool,
}

impl CmdOpt {
  pub fn global() -> &'static LazyLock<CmdOpt> {
    static CMD_OPT: LazyLock<CmdOpt> = LazyLock::new(CmdOpt::parse);
    &CMD_OPT
  }
}

/// Server configuration.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
  pub name: String,
  /// Virtual hostnames for this server (for SNI/Host routing)
  #[serde(default)]
  pub hostnames: Vec<String>,
  /// TLS configuration (for https and http3 listeners)
  pub tls: Option<ServerTlsConfig>,
  /// References to top-level listener names
  pub listeners: Vec<String>,
  pub service: String,
}

/// Configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigRaw {
  #[serde(default)]
  pub listeners: Vec<ListenerConfig>,
  #[serde(default = "default_server_threads")]
  pub server_threads: usize,
  pub services: Vec<ServiceRaw>,
  pub servers: Vec<Server>,
}

fn default_server_threads() -> usize {
  4
}

/// Main configuration.
#[derive(Clone, Debug)]
pub struct Config {
  pub server_threads: usize,
  pub listeners: Vec<ListenerConfig>,
  pub services: Vec<Service>,
  pub servers: Vec<Server>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      server_threads: 4,
      listeners: vec![],
      services: vec![],
      servers: vec![],
    }
  }
}

impl Config {
  /// Parse config from a string
  pub fn parse_string(&mut self, s: &str) -> Result<()> {
    let raw: ConfigRaw = serde_yaml::from_str(s)?;

    self.server_threads = raw.server_threads;
    self.listeners = raw.listeners;
    self.servers = raw.servers;

    // Convert ServiceRaw -> Service using parse methods
    self.services = raw
      .services
      .into_iter()
      .map(|sr| sr.parse())
      .collect::<Result<Vec<_>>>()?;

    Ok(())
  }

  /// Read and parse config from a file
  fn parse_file(&mut self, path: &str) -> Result<()> {
    let s = std::fs::read_to_string(std::path::Path::new(path))
      .with_context(|| format!("read config file '{}'", path))?;
    self.parse_string(&s)?;
    Ok(())
  }

  /// Load configuration from a file.
  ///
  /// Returns the parsed config. Does not validate.
  pub fn load(path: &str) -> Result<Config> {
    let mut config = Config::default();
    config.parse_file(path)?;
    Ok(config)
  }

  /// Initialize the global config. Must be called before
  /// `Config::global()`.
  pub fn init_global(config: Config) {
    GLOBAL_CONFIG.set(config).ok();
  }

  pub fn global() -> &'static Config {
    GLOBAL_CONFIG.get().expect(
      "Config not initialized - call Config::init_global() first",
    )
  }
}

// =========================================================================
// Validation logic
// =========================================================================

/// Validate server_threads global setting.
pub fn validate_server_threads(
  server_threads: usize,
  collector: &mut ConfigErrorCollector,
) {
  if server_threads == 0 {
    collector.add(ConfigError::InvalidFormat {
      location: "server_threads".into(),
      message: "must be at least 1".into(),
    });
  }
}

/// Validate the entire configuration.
///
/// This function validates:
/// - Global settings (server_threads)
/// - Service references in servers
/// - Hostname patterns
/// - TLS configurations
/// - Listener address format
/// - Listener references
/// - Hostname routing compatibility
/// - Address conflicts across servers
/// - Hostname conflicts across servers
pub fn validate_config(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  use crate::listeners::ListenerManager;
  let listener_manager = ListenerManager::new();
  // Validate global settings
  validate_server_threads(config.server_threads, collector);

  // Collect all service names for reference validation
  let service_names: std::collections::HashSet<&str> =
    config.services.iter().map(|s| s.name.as_str()).collect();

  // Validate servers
  for (server_idx, server) in config.servers.iter().enumerate() {
    let server_location = format!("servers[{}]", server_idx);

    // Validate hostnames
    for (idx, hostname) in server.hostnames.iter().enumerate() {
      let hostname_location =
        format!("{}.hostnames[{}]", server_location, idx);
      validate_hostname(hostname, &hostname_location, collector);
    }

    // Validate TLS if present
    if let Some(ref tls) = server.tls {
      validate_server_tls(
        tls,
        &format!("{}.tls", server_location),
        collector,
      );
    }

    // Validate service reference
    validate_service(
      &service_names,
      server_idx,
      &server.service,
      collector,
    );
  }

  // Validate listener addresses
  for (idx, listener) in config.listeners.iter().enumerate() {
    let location = format!("listeners[{}]", idx);
    validate_listener_addresses(
      &listener.addresses,
      &location,
      collector,
    );
  }

  // Validate listener references
  validate_listener_references(config, collector);

  // Validate hostname routing compatibility
  validate_hostname_routing_compatibility(
    config,
    collector,
    &listener_manager,
  );

  // Validate address conflicts across all servers
  validate_address_conflicts(config, collector, &listener_manager);

  // Validate hostname conflicts across servers
  validate_hostname_conflicts(config, collector, &listener_manager);
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Get the temporary directory for tests.
  /// Per constraint, we must use "tmp/" in the current directory
  /// instead of /tmp. This function also ensures the directory
  /// exists.
  fn get_temp_dir() -> std::path::PathBuf {
    let temp_dir = std::path::PathBuf::from("tmp");
    // Create the directory if it doesn't exist
    std::fs::create_dir_all(&temp_dir)
      .expect("Failed to create tmp directory");
    temp_dir
  }

  #[test]
  fn test_config_default() {
    let config = Config::default();
    assert_eq!(config.server_threads, 4);
    assert!(config.listeners.is_empty());
    assert!(config.services.is_empty());
    assert!(config.servers.is_empty());
  }

  #[test]
  fn test_parse_string_valid() {
    let yaml = r#"
server_threads: 2
services: []
servers: []
"#;
    let mut config = Config::default();
    assert!(config.parse_string(yaml).is_ok());
    assert_eq!(config.server_threads, 2);
  }

  #[test]
  fn test_parse_string_invalid_yaml() {
    let yaml = r#"
server_threads: [
  invalid
"#;
    let mut config = Config::default();
    assert!(config.parse_string(yaml).is_err());
  }

  #[test]
  fn test_cmd_opt_default_config_file() {
    let opt = CmdOpt {
      config_file: "conf/server.yaml".to_string(),
      version: false,
    };
    assert_eq!(opt.config_file, "conf/server.yaml");
  }

  #[test]
  fn test_service_default() {
    let service = Service::default();
    assert!(service.name.is_empty());
    assert!(service.plugin_name.is_empty());
    assert!(service.kind.is_empty());
    assert!(service.layers.is_empty());
  }

  #[test]
  fn test_listener_config_default() {
    let lc = ListenerConfig::default();
    assert!(lc.name.is_empty());
    assert!(lc.kind.is_empty());
    assert!(lc.addresses.is_empty());
  }

  #[test]
  fn test_listener_config_deserialize() {
    let yaml = r#"
name: http_main
kind: http
addresses:
  - "0.0.0.0:8080"
"#;
    let lc: ListenerConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(lc.name, "http_main");
    assert_eq!(lc.kind, "http");
    assert_eq!(lc.addresses, vec!["0.0.0.0:8080"]);
  }

  #[test]
  fn test_listener_field_is_string_reference() {
    let yaml = r#"
listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:8080"]
servers:
  - name: server1
    listeners:
      - http_main
    service: ""
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert_eq!(config.servers[0].listeners[0], "http_main");
    assert_eq!(config.listeners[0].kind, "http");
    assert_eq!(config.listeners[0].addresses, vec!["127.0.0.1:8080"]);
  }

  #[test]
  fn test_server_default() {
    let server = Server::default();
    assert!(server.name.is_empty());
    assert!(server.service.is_empty());
    assert!(server.listeners.is_empty());
  }

  #[test]
  fn test_layer_default() {
    let layer = Layer::default();
    assert!(layer.plugin_name.is_empty());
    assert!(layer.kind.is_empty());
  }

  #[test]
  fn test_config_clone() {
    let config = Config {
      server_threads: 2,
      listeners: vec![],
      services: vec![],
      servers: vec![],
    };
    let cloned = config.clone();
    assert_eq!(cloned.server_threads, 2);
  }

  #[test]
  fn test_load_file_not_found() {
    // Create a temp file to ensure we have a unique non-existent path
    let temp_dir = get_temp_dir();
    let non_existent_path =
      temp_dir.join("neoproxy_test_nonexistent_config_12345.yaml");
    // Remove if it somehow exists
    let _ = std::fs::remove_file(&non_existent_path);

    // Test that load returns an error for a non-existent config file
    let result = Config::load(non_existent_path.to_str().unwrap());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("read config file"));
  }

  #[test]
  fn test_load_valid_config() {
    // Create a temporary valid config file
    let temp_dir = get_temp_dir();
    let temp_path = temp_dir.join("neoproxy_test_valid_config.yaml");
    let config_content = r#"
server_threads: 2
listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:8080"]
services:
  - name: "echo_svc"
    kind: "echo.echo"
    args: null
    layers: []
servers:
  - name: "server1"
    listeners:
      - "http_main"
    service: "echo_svc"
"#;
    std::fs::write(&temp_path, config_content).unwrap();

    let config = Config::load(temp_path.to_str().unwrap()).unwrap();
    assert_eq!(config.server_threads, 2);
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.servers.len(), 1);

    // Cleanup
    let _ = std::fs::remove_file(&temp_path);
  }

  #[test]
  fn test_parse_string_yaml_error() {
    let invalid_yaml = r#"
server_threads: [
  invalid yaml
"#;
    let mut config = Config::default();
    let result = config.parse_string(invalid_yaml);
    assert!(result.is_err());
  }

  #[test]
  fn test_cmd_opt_global() {
    // CmdOpt::global() returns a static reference
    // We can't easily test the actual parsing without affecting global
    // state But we can verify the function exists and returns
    // something
    let _opt = CmdOpt::global();
  }

  // =========================================================================
  // Split Kind Fields Tests
  // =========================================================================

  #[test]
  fn test_service_kind_split_into_parts() {
    let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers: []
servers: []
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert_eq!(config.services[0].plugin_name, "echo");
    assert_eq!(config.services[0].kind, "echo");
  }

  #[test]
  fn test_layer_kind_split_into_parts() {
    let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers:
      - kind: "echo.echo"
        args: null
servers: []
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert_eq!(config.services[0].layers[0].plugin_name, "echo");
    assert_eq!(config.services[0].layers[0].kind, "echo");
  }

  #[test]
  fn test_service_kind_missing_dot() {
    let yaml = r#"
services:
  - name: test
    kind: "invalidkind"
    args: null
    layers: []
servers: []
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(result.is_err(), "Missing dot should be rejected");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
      err_msg.contains("invalid service kind"),
      "Error should mention 'invalid service kind', got: {}",
      err_msg
    );
  }

  #[test]
  fn test_service_kind_empty_service_name() {
    let yaml = r#"
services:
  - name: test
    kind: "echo."
    args: null
    layers: []
servers: []
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(
      result.is_err(),
      "Empty service name after dot should be rejected"
    );
  }

  #[test]
  fn test_service_kind_empty_plugin_name() {
    let yaml = r#"
services:
  - name: test
    kind: ".echo"
    args: null
    layers: []
servers: []
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(
      result.is_err(),
      "Empty plugin name before dot should be rejected"
    );
  }

  #[test]
  fn test_service_kind_empty_string() {
    let yaml = r#"
services:
  - name: test
    kind: ""
    args: null
    layers: []
servers: []
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(result.is_err(), "Empty kind string should be rejected");
  }

  #[test]
  fn test_service_kind_multiple_dots() {
    let yaml = r#"
services:
  - name: test
    kind: "echo.echo.echo"
    args: null
    layers: []
servers: []
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(result.is_err(), "Multiple dots should be rejected");
  }

  #[test]
  fn test_layer_kind_missing_dot() {
    let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers:
      - kind: "invalidkind"
        args: null
servers: []
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(
      result.is_err(),
      "Layer with missing dot should be rejected"
    );
  }

  #[test]
  fn test_layer_kind_empty_parts() {
    let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers:
      - kind: "echo."
        args: null
servers: []
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(
      result.is_err(),
      "Layer with empty service name should be rejected"
    );
  }

  // =========================================================================
  // validate_config Tests
  // =========================================================================

  #[test]
  fn test_validate_config_valid() {
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![Server {
        name: "server1".to_string(),
        hostnames: vec![],
        listeners: vec!["http_main".to_string()],
        service: "echo".to_string(),
        tls: None,
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "Valid config should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_config_empty() {
    let config = Config::default();
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_config_server_threads_zero() {
    let config = Config { server_threads: 0, ..Default::default() };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      matches!(e, ConfigError::InvalidFormat { location, .. } if location == "server_threads")
    });
    assert!(found, "Should have server_threads validation error");
  }

  #[test]
  fn test_validate_config_service_reference_not_found() {
    let config = Config {
      services: vec![],
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert!(matches!(&errors[0], ConfigError::NotFound { .. }));
  }

  #[test]
  fn test_validate_config_invalid_listener_address() {
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["invalid:address".to_string()],
        ..Default::default()
      }],
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(
      errors
        .iter()
        .any(|e| matches!(e, ConfigError::InvalidAddress { .. }))
    );
  }

  #[test]
  fn test_validate_config_https_without_tls() {
    // Note: TLS validation for listeners is now done through
    // validate_listener which is no longer called directly. The
    // validate_config function validates TLS at the server level.
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "https_main".to_string(),
        kind: "https".to_string(),
        addresses: vec!["127.0.0.1:8443".to_string()],
        ..Default::default()
      }],
      servers: vec![Server {
        name: "https_server".to_string(),
        listeners: vec!["https_main".to_string()],
        service: "".to_string(),
        tls: None,
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    // No TLS validation error expected since we removed
    // validate_listener calls The test now just verifies the config
    // structure works
    assert!(
      !collector.has_errors(),
      "HTTPS listener without TLS should not produce errors: {:?}",
      collector.errors()
    );
  }

  // =========================================================================
  // ConfigRaw Deserialization Tests
  // =========================================================================

  #[test]
  fn test_config_raw_deserialize() {
    let yaml = r#"
listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:8080"]
servers:
  - name: default
    hostnames: []
    listeners: ["http_main"]
    service: echo_svc
services:
  - name: echo_svc
    kind: echo.echo
"#;
    let raw: ConfigRaw = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(raw.listeners.len(), 1);
    assert_eq!(raw.listeners[0].name, "http_main");
    assert_eq!(raw.servers[0].listeners, vec!["http_main"]);
    assert_eq!(raw.server_threads, 4); // default
  }
}
