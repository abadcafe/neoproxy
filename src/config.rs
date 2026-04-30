//! Configuration types, parsing, and validation.
//!
//! This module provides:
//! - Core configuration types (Config, Server, Service, Listener)
//! - Configuration parsing from YAML files
//! - Configuration validation with detailed error reporting
//! - `SerializedArgs` type for configuration data

mod access_log;
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
pub use self::access_log::{
  AccessLogConfig, AccessLogOverride, HumanDuration, LogFormat,
  validate_access_log_config,
};
pub use self::auth::{
  ListenerAuthConfig, UserConfig, UserCredential,
  validate_listener_auth_config, validate_users,
};
pub use self::error::{ConfigErrorCollector, ConfigErrorKind};
pub use self::listener::{
  Listener, extract_addresses, validate_address_conflicts,
  validate_hostname, validate_listener, validate_socks5_hostnames,
};
pub use self::service::{Layer, Service, ServiceRaw, validate_service};
pub use self::tls::{
  CertificateConfig, ServerTlsConfig, validate_server_tls,
};

/// Serialized configuration arguments.
///
/// A type alias for `serde_yaml::Value`, used to pass configuration
/// data from YAML files to listener and service builders.
pub type SerializedArgs = serde_yaml::Value;

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
#[serde(default)]
pub struct Server {
  pub name: String,
  /// Virtual hostnames for this server (for SNI/Host routing)
  #[serde(default)]
  pub hostnames: Vec<String>,
  /// TLS configuration (for https and http3 listeners)
  pub tls: Option<ServerTlsConfig>,
  /// User authentication configuration
  #[serde(default)]
  pub users: Option<Vec<UserConfig>>,
  pub listeners: Vec<Listener>,
  pub service: String,
  #[serde(default)]
  pub access_log: Option<AccessLogOverride>,
}

/// Configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
struct ConfigRaw {
  pub worker_threads: usize,
  pub log_directory: String,
  #[serde(default)]
  pub access_log: Option<AccessLogConfig>,
  pub services: Vec<ServiceRaw>,
  pub servers: Vec<Server>,
}

/// Main configuration.
#[derive(Clone, Debug)]
pub struct Config {
  pub worker_threads: usize,
  pub log_directory: String,
  pub access_log: Option<AccessLogConfig>,
  pub services: Vec<Service>,
  pub servers: Vec<Server>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      worker_threads: 1,
      log_directory: String::from("logs/"),
      access_log: None,
      services: vec![],
      servers: vec![],
    }
  }
}

/// Validate and split a kind string into (first_part, second_part).
///
/// Requires exactly one dot separator with non-empty parts on both sides.
/// Returns a `ConfigParseError` with `InvalidFormat` kind for any violation.
fn validate_and_split_kind<'a>(
  kind: &'a str,
  location: &str,
) -> Result<(&'a str, &'a str)> {
  if kind.is_empty() {
    return Err(
      ConfigParseError {
        message: format!(
          "{}: invalid format '', expected 'plugin_name.service_name'",
          location
        ),
        kind: ConfigErrorKind::InvalidFormat,
      }
      .into(),
    );
  }

  let dot_count = kind.matches('.').count();
  if dot_count != 1 {
    return Err(ConfigParseError {
      message: format!(
        "{}: invalid format '{}', expected 'plugin_name.service_name'",
        location, kind
      ),
      kind: ConfigErrorKind::InvalidFormat,
    }
    .into());
  }

  let parts: Vec<&str> = kind.splitn(2, '.').collect();
  let first = parts[0];
  let second = parts[1];

  if first.is_empty() || second.is_empty() {
    return Err(ConfigParseError {
      message: format!(
        "{}: invalid format '{}', expected 'plugin_name.service_name'",
        location, kind
      ),
      kind: ConfigErrorKind::InvalidFormat,
    }
    .into());
  }

  Ok((first, second))
}

/// A parse error that carries its error kind directly.
///
/// Kind format validation errors carry `InvalidFormat`, YAML parse errors
/// carry `YamlParse`.
#[derive(Debug)]
pub struct ConfigParseError {
  pub message: String,
  pub kind: ConfigErrorKind,
}

impl std::fmt::Display for ConfigParseError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.message)
  }
}

impl std::error::Error for ConfigParseError {}

impl Config {
  /// Parse config from a string
  pub fn parse_string(&mut self, s: &str) -> Result<()> {
    let raw: ConfigRaw =
      serde_yaml::from_str(s).map_err(|e| ConfigParseError {
        message: format!("parse config text failed: {}", e),
        kind: ConfigErrorKind::YamlParse,
      })?;

    self.worker_threads = raw.worker_threads;
    self.log_directory = raw.log_directory;
    self.access_log = raw.access_log;

    // Store servers (listener kind validation below)
    self.servers = raw.servers;

    // Validate listener kinds (non-empty only)
    for (server_idx, server) in self.servers.iter().enumerate() {
      for (listener_idx, listener) in
        server.listeners.iter().enumerate()
      {
        if listener.listener_name.is_empty() {
          return Err(ConfigParseError {
            message: format!(
              "servers[{}].listeners[{}].kind: invalid format '', expected 'protocol_name'",
              server_idx, listener_idx
            ),
            kind: ConfigErrorKind::InvalidFormat,
          }
          .into());
        }
      }
    }

    // Convert ServiceRaw -> Service with format validation
    self.services = raw
      .services
      .into_iter()
      .enumerate()
      .map(|(idx, raw_svc)| {
        let location = format!("services[{}].kind", idx);
        let (plugin_name, service_name) =
          validate_and_split_kind(&raw_svc.kind, &location)?;

        // Validate layer kinds
        let layers: Vec<Layer> = raw_svc
          .layers
          .into_iter()
          .enumerate()
          .map(|(layer_idx, raw_layer)| {
            let layer_location =
              format!("services[{}].layers[{}].kind", idx, layer_idx);
            let (lp, ln) = validate_and_split_kind(
              &raw_layer.kind,
              &layer_location,
            )?;

            Ok(Layer {
              plugin_name: lp.to_string(),
              layer_name: ln.to_string(),
              args: raw_layer.args,
            })
          })
          .collect::<Result<Vec<Layer>>>()?;

        Ok(Service {
          name: raw_svc.name,
          plugin_name: plugin_name.to_string(),
          service_name: service_name.to_string(),
          args: raw_svc.args,
          layers,
        })
      })
      .collect::<Result<Vec<Service>>>()?;

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

  /// Initialize the global config. Must be called before `Config::global()`.
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

/// Validate worker_threads global setting.
pub fn validate_worker_threads(
  worker_threads: usize,
  collector: &mut ConfigErrorCollector,
) {
  if worker_threads == 0 {
    collector.add(
      "worker_threads",
      "must be at least 1".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
  }
}

/// Validate the entire configuration.
///
/// This function validates:
/// - Global settings (worker_threads)
/// - Kind format for all services and listeners
/// - Service references in servers
/// - Address parsing in listener args
/// - Listener TLS requirements
/// - Hostname patterns
/// - User configurations
/// - TLS configurations
/// - HTTP/3 specific configurations
/// - Address conflicts across servers
pub fn validate_config(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  // Validate global settings
  validate_worker_threads(config.worker_threads, collector);

  // Validate access_log if present
  if let Some(ref access_log) = config.access_log {
    validate_access_log_config(access_log, collector);
  }

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

    // Validate users if present
    if let Some(ref users) = server.users {
      validate_users(
        users,
        &format!("{}.users", server_location),
        collector,
      );
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

    // Validate listeners
    for (listener_idx, listener) in server.listeners.iter().enumerate()
    {
      let listener_location =
        format!("{}.listeners[{}]", server_location, listener_idx);
      validate_listener(
        listener,
        &listener_location,
        server.tls.as_ref(),
        collector,
      );
    }
  }

  // Validate SOCKS5 + hostnames semantic
  validate_socks5_hostnames(config, collector);

  // Validate address conflicts across all servers
  validate_address_conflicts(config, collector);
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Get the temporary directory for tests.
  /// Per constraint, we must use "tmp/" in the current directory instead of /tmp.
  /// This function also ensures the directory exists.
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
    assert_eq!(config.worker_threads, 1);
    assert_eq!(config.log_directory, "logs/");
    assert!(config.services.is_empty());
    assert!(config.servers.is_empty());
  }

  #[test]
  fn test_parse_string_valid() {
    let yaml = r#"
worker_threads: 2
log_directory: "test_logs/"
services: []
servers: []
"#;
    let mut config = Config::default();
    assert!(config.parse_string(yaml).is_ok());
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.log_directory, "test_logs/");
  }

  #[test]
  fn test_parse_string_invalid_yaml() {
    let yaml = r#"
worker_threads: [
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
    assert!(service.service_name.is_empty());
    assert!(service.layers.is_empty());
  }

  #[test]
  fn test_listener_default() {
    let listener = Listener::default();
    assert!(listener.listener_name.is_empty());
  }

  #[test]
  fn test_listener_field_is_listener_name() {
    let yaml = r#"
servers:
  - name: server1
    listeners:
      - kind: http
        args:
          addresses: ["127.0.0.1:8080"]
    service: ""
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert_eq!(config.servers[0].listeners[0].listener_name, "http");
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
    assert!(layer.layer_name.is_empty());
  }

  #[test]
  fn test_config_clone() {
    let config = Config {
      worker_threads: 2,
      log_directory: "test/".to_string(),
      access_log: None,
      services: vec![],
      servers: vec![],
    };
    let cloned = config.clone();
    assert_eq!(cloned.worker_threads, 2);
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
worker_threads: 2
log_directory: "logs/"
services:
  - name: "echo_svc"
    kind: "echo.echo"
    args: null
    layers: []
servers:
  - name: "server1"
    listeners:
      - kind: "http"
        args:
          addresses: ["127.0.0.1:8080"]
    service: "echo_svc"
"#;
    std::fs::write(&temp_path, config_content).unwrap();

    let config = Config::load(temp_path.to_str().unwrap()).unwrap();
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.servers.len(), 1);

    // Validate the loaded config
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "Loaded config should pass validation: {:?}",
      collector.errors()
    );

    // Cleanup
    let _ = std::fs::remove_file(&temp_path);
  }

  #[test]
  fn test_parse_string_yaml_error() {
    let invalid_yaml = r#"
worker_threads: [
  invalid yaml
"#;
    let mut config = Config::default();
    let result = config.parse_string(invalid_yaml);
    assert!(result.is_err());
  }

  #[test]
  fn test_cmd_opt_global() {
    // CmdOpt::global() returns a static reference
    // We can't easily test the actual parsing without affecting global state
    // But we can verify the function exists and returns something
    let _opt = CmdOpt::global();
  }

  // =========================================================================
  // Access Log Config Integration Tests
  // =========================================================================

  #[test]
  fn test_config_with_access_log() {
    let yaml = r#"
worker_threads: 1
log_directory: logs/
access_log:
  enabled: true
  path_prefix: "access.log"
  format: text
  buffer: 32kb
  flush: 1s
  max_size: 200mb
services: []
servers: []
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert!(config.access_log.is_some());
    let al = config.access_log.as_ref().unwrap();
    assert!(al.enabled);
    assert_eq!(al.path_prefix, "access.log");
  }

  #[test]
  fn test_config_without_access_log() {
    let yaml = r#"
worker_threads: 1
log_directory: logs/
services: []
servers: []
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert!(config.access_log.is_none());
  }

  #[test]
  fn test_server_with_access_log_override() {
    let yaml = r#"
worker_threads: 1
log_directory: logs/
access_log:
  enabled: true
  format: text
servers:
  - name: http_proxy
    service: tunnel
    access_log:
      path_prefix: "http_access.log"
      format: json
    listeners: []
services:
  - name: tunnel
    kind: connect_tcp.connect_tcp
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert!(config.access_log.is_some());
    assert!(config.servers[0].access_log.is_some());
    let server_al = config.servers[0].access_log.as_ref().unwrap();
    assert_eq!(
      server_al.path_prefix,
      Some("http_access.log".to_string())
    );
    // format is explicitly set
    assert!(matches!(server_al.format, Some(LogFormat::Json)));
    // buffer is NOT set, should be None (inherited from top-level at merge time)
    assert!(server_al.buffer.is_none());
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
    assert_eq!(config.services[0].service_name, "echo");
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
    assert_eq!(config.services[0].layers[0].layer_name, "echo");
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
      err_msg.contains("invalid format"),
      "Error should mention 'invalid format', got: {}",
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

  #[test]
  fn test_listener_kind_empty_string() {
    let yaml = r#"
services: []
servers:
  - name: server1
    listeners:
      - kind: ""
        args:
          addresses: ["127.0.0.1:8080"]
    service: ""
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(
      result.is_err(),
      "Listener with empty kind should be rejected"
    );
  }

  // =========================================================================
  // Parse error carries ConfigErrorKind directly
  // =========================================================================

  #[test]
  fn test_parse_string_invalid_kind_returns_config_error_with_kind() {
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
    assert!(result.is_err());
    let err = result.unwrap_err();
    // Verify it's a ConfigParseError with InvalidFormat kind
    let config_err = err
      .downcast_ref::<ConfigParseError>()
      .expect("should be ConfigParseError");
    assert_eq!(
      config_err.kind,
      ConfigErrorKind::InvalidFormat,
      "kind validation error should have InvalidFormat kind"
    );
  }

  #[test]
  fn test_parse_string_yaml_error_returns_config_error_with_yaml_kind()
  {
    let yaml = "worker_threads: [";
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let config_err = err
      .downcast_ref::<ConfigParseError>()
      .expect("should be ConfigParseError");
    assert_eq!(
      config_err.kind,
      ConfigErrorKind::YamlParse,
      "YAML parse error should have YamlParse kind"
    );
  }

  #[test]
  fn test_parse_string_listener_empty_kind_returns_config_error() {
    let yaml = r#"
services: []
servers:
  - name: server1
    listeners:
      - kind: ""
        args:
          addresses: ["127.0.0.1:8080"]
    service: ""
"#;
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let config_err = err
      .downcast_ref::<ConfigParseError>()
      .expect("should be ConfigParseError");
    assert_eq!(
      config_err.kind,
      ConfigErrorKind::InvalidFormat,
      "listener empty kind should have InvalidFormat kind"
    );
  }

  // =========================================================================
  // validate_config Tests
  // =========================================================================

  #[test]
  fn test_validate_config_valid() {
    let config = Config {
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![Server {
        name: "server1".to_string(),
        hostnames: vec![],
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args: serde_yaml::from_str(
            r#"{addresses: ["127.0.0.1:8080"]}"#,
          )
          .unwrap(),
        }],
        service: "echo".to_string(),
        tls: None,
        users: None,
        access_log: None,
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
  fn test_validate_config_worker_threads_zero() {
    let config = Config { worker_threads: 0, ..Default::default() };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "worker_threads" && e.message.contains("at least 1")
    });
    assert!(found, "Should have worker_threads validation error");
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
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(
      errors[0].message.contains("service 'nonexistent' not found")
    );
  }

  #[test]
  fn test_validate_config_invalid_listener_address() {
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args: serde_yaml::from_str(
            r#"{addresses: ["invalid:address"]}"#,
          )
          .unwrap(),
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_config_https_without_tls() {
    let config = Config {
      servers: vec![Server {
        name: "https_server".to_string(),
        listeners: vec![Listener {
          listener_name: "https".to_string(),
          args: serde_yaml::from_str(
            r#"{addresses: ["127.0.0.1:8443"]}"#,
          )
          .unwrap(),
        }],
        service: "".to_string(),
        tls: None,
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(found, "Should have TLS required error for https");
  }
}
