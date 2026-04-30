use std::collections::HashMap;
use std::fs;
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use byte_unit::Byte;
use clap::Parser;
use serde::Deserialize;

use crate::config_validator::ConfigErrorKind;
use crate::plugin::SerializedArgs;

/// Global config instance, initialized via `Config::init_global()`.
static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

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

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Listener {
  #[serde(rename = "kind")]
  pub listener_name: String,
  pub args: SerializedArgs,
}

/// Certificate configuration (cert + key pair)
#[derive(Deserialize, Clone, Debug)]
pub struct CertificateConfig {
  /// Path to certificate file (PEM format)
  pub cert_path: String,
  /// Path to private key file (PEM format)
  pub key_path: String,
}

/// Server-level TLS configuration
#[derive(Deserialize, Clone, Debug)]
pub struct ServerTlsConfig {
  /// List of certificates (cert_path + key_path pairs)
  pub certificates: Vec<CertificateConfig>,
  /// Optional client CA certificates for mTLS
  #[serde(default)]
  pub client_ca_certs: Option<Vec<String>>,
}

/// User credential configuration
#[derive(Deserialize, Clone, Debug)]
pub struct UserConfig {
  /// Username for authentication
  pub username: String,
  /// Password for authentication
  pub password: String,
}

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

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
struct LayerRaw {
  pub kind: String,
  pub args: SerializedArgs,
}

#[derive(Default, Clone, Debug)]
pub struct Layer {
  pub plugin_name: String,
  pub layer_name: String,
  pub args: SerializedArgs,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
struct ServiceRaw {
  pub name: String,
  pub kind: String,
  pub args: SerializedArgs,
  pub layers: Vec<LayerRaw>,
}

#[derive(Default, Clone, Debug)]
pub struct Service {
  pub name: String,
  pub plugin_name: String,
  pub service_name: String,
  pub args: SerializedArgs,
  pub layers: Vec<Layer>,
}

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

// ============================================================================
// Access Log Configuration Types
// ============================================================================

/// Log output format.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
  #[default]
  Text,
  Json,
}

/// Human-readable duration (e.g., "1s", "5m", "1h30m").
#[derive(Debug, Clone, Copy)]
pub struct HumanDuration(pub Duration);

impl<'de> Deserialize<'de> for HumanDuration {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    let duration = humantime::parse_duration(s.trim())
      .map_err(|e| serde::de::Error::custom(e.to_string()))?;
    Ok(HumanDuration(duration))
  }
}

fn default_enabled() -> bool {
  true
}

fn default_path_prefix() -> String {
  "access.log".to_string()
}

fn default_format() -> LogFormat {
  LogFormat::default()
}

fn default_buffer_size() -> Byte {
  Byte::from_u64(32 * 1024)
}

fn default_flush_interval() -> HumanDuration {
  HumanDuration(Duration::from_secs(1))
}

fn default_max_size() -> Byte {
  Byte::from_u64(200 * 1024 * 1024)
}

/// Full access log config with all fields resolved (used as top-level config).
#[derive(Debug, Clone, Deserialize)]
pub struct AccessLogConfig {
  #[serde(default = "default_enabled")]
  pub enabled: bool,

  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,

  #[serde(default = "default_format")]
  pub format: LogFormat,

  #[serde(default = "default_buffer_size")]
  pub buffer: Byte,

  #[serde(default = "default_flush_interval")]
  pub flush: HumanDuration,

  #[serde(default = "default_max_size")]
  pub max_size: Byte,
}

impl Default for AccessLogConfig {
  fn default() -> Self {
    Self {
      enabled: default_enabled(),
      path_prefix: default_path_prefix(),
      format: default_format(),
      buffer: default_buffer_size(),
      flush: default_flush_interval(),
      max_size: default_max_size(),
    }
  }
}

impl AccessLogConfig {
  /// Merge with a server-level override config.
  /// Only fields explicitly set in the override (Some) take precedence.
  /// Fields not set in the override (None) are inherited from self.
  pub fn merge(&self, override_config: &AccessLogOverride) -> Self {
    Self {
      enabled: override_config.enabled.unwrap_or(self.enabled),
      path_prefix: override_config
        .path_prefix
        .clone()
        .unwrap_or_else(|| self.path_prefix.clone()),
      format: override_config.format.unwrap_or(self.format),
      buffer: override_config.buffer.unwrap_or(self.buffer),
      flush: override_config.flush.unwrap_or(self.flush),
      max_size: override_config.max_size.unwrap_or(self.max_size),
    }
  }
}

/// Server-level access log override config.
/// All fields are Option so that only explicitly set fields
/// override the top-level config. Unset fields are inherited.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AccessLogOverride {
  pub enabled: Option<bool>,
  pub path_prefix: Option<String>,
  pub format: Option<LogFormat>,
  pub buffer: Option<Byte>,
  pub flush: Option<HumanDuration>,
  pub max_size: Option<Byte>,
}

// ============================================================================
// Listener Authentication Configuration Types
// ============================================================================

/// User credential for password authentication.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UserCredential {
  /// Username.
  pub username: String,
  /// Password (plaintext).
  pub password: String,
}

/// Listener authentication configuration.
///
/// Field presence determines auth type:
/// - `users` non-empty → password authentication
/// - `client_ca_path` present → TLS client cert authentication
/// - Both present → dual-factor AND authentication
///
/// At least one field must be configured. `auth: {}` (both empty) is invalid.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct ListenerAuthConfig {
  /// User credentials for password authentication.
  /// Non-empty → password auth enabled.
  /// Empty or missing → no password auth.
  #[serde(default)]
  pub users: Vec<UserCredential>,
  /// Client CA certificate path for TLS client cert authentication.
  /// Present → cert auth enabled.
  #[serde(default)]
  pub client_ca_path: Option<String>,
}

impl ListenerAuthConfig {
  /// Get users as a HashMap for password lookup.
  ///
  /// Returns `None` if no users are configured (empty array).
  pub fn users_map(&self) -> Option<HashMap<String, String>> {
    if self.users.is_empty() {
      None
    } else {
      Some(
        self
          .users
          .iter()
          .map(|u| (u.username.clone(), u.password.clone()))
          .collect(),
      )
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
    let s = fs::read_to_string(std::path::Path::new(path))
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config_validator::ConfigErrorCollector;

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
    use crate::config_validator::validate_config;

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
  // Access Log Config Tests
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
    assert!(matches!(server_al.format, Some(super::LogFormat::Json)));
    // buffer is NOT set, should be None (inherited from top-level at merge time)
    assert!(server_al.buffer.is_none());
  }

  // =========================================================================
  // TLS Configuration Tests
  // =========================================================================

  #[test]
  fn test_certificate_config_deserialize() {
    let yaml = r#"
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
"#;
    let cert: CertificateConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cert.cert_path, "/path/to/cert.pem");
    assert_eq!(cert.key_path, "/path/to/key.pem");
  }

  #[test]
  fn test_server_tls_config_deserialize_single_cert() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 1);
    assert_eq!(tls.certificates[0].cert_path, "/path/to/cert.pem");
    assert_eq!(tls.certificates[0].key_path, "/path/to/key.pem");
    assert!(tls.client_ca_certs.is_none());
  }

  #[test]
  fn test_server_tls_config_deserialize_multiple_certs() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert1.pem"
    key_path: "/path/to/key1.pem"
  - cert_path: "/path/to/cert2.pem"
    key_path: "/path/to/key2.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 2);
  }

  #[test]
  fn test_server_tls_config_deserialize_with_client_ca() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
client_ca_certs:
  - "/path/to/ca1.pem"
  - "/path/to/ca2.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 1);
    assert!(tls.client_ca_certs.is_some());
    let client_cas = tls.client_ca_certs.unwrap();
    assert_eq!(client_cas.len(), 2);
    assert_eq!(client_cas[0], "/path/to/ca1.pem");
    assert_eq!(client_cas[1], "/path/to/ca2.pem");
  }

  #[test]
  fn test_server_tls_config_missing_certificates() {
    let yaml = r#"{}"#;
    let result: Result<ServerTlsConfig, _> = serde_yaml::from_str(yaml);
    // certificates field is required
    assert!(result.is_err());
  }

  #[test]
  fn test_certificate_config_missing_fields() {
    // Missing cert_path
    let yaml = r#"key_path: "/path/to/key.pem""#;
    let result: Result<CertificateConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err());

    // Missing key_path
    let yaml = r#"cert_path: "/path/to/cert.pem""#;
    let result: Result<CertificateConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err());
  }

  // =========================================================================
  // SOCKS5 Hostname Validation Tests
  // =========================================================================

  // =========================================================================
  // Hostname Duplicate Detection Tests (Task 002)
  // =========================================================================

  // =========================================================================
  // SOCKS5 Conflict via Default Server Check Tests (Task 003)
  // =========================================================================

  // =========================================================================
  // Worker Threads Validation Tests
  // =========================================================================

  // =========================================================================
  // Split Kind Fields Tests (Task 003)
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
  // TLS Required for HTTPS/HTTP3 Tests
  // =========================================================================

  // =========================================================================
  // CR-010: Parse error carries ConfigErrorKind directly (not via string match)
  // =========================================================================

  #[test]
  fn test_parse_string_invalid_kind_returns_config_error_with_kind() {
    // CR-010: parse_string() errors from kind validation should carry
    // ConfigErrorKind directly, not require string-based classification
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
      .downcast_ref::<super::ConfigParseError>()
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
    // CR-010: YAML parse errors should carry YamlParse kind
    let yaml = "worker_threads: [";
    let mut config = Config::default();
    let result = config.parse_string(yaml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let config_err = err
      .downcast_ref::<super::ConfigParseError>()
      .expect("should be ConfigParseError");
    assert_eq!(
      config_err.kind,
      ConfigErrorKind::YamlParse,
      "YAML parse error should have YamlParse kind"
    );
  }

  #[test]
  fn test_parse_string_listener_empty_kind_returns_config_error() {
    // CR-010: Listener empty kind should also carry InvalidFormat kind
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
      .downcast_ref::<super::ConfigParseError>()
      .expect("should be ConfigParseError");
    assert_eq!(
      config_err.kind,
      ConfigErrorKind::InvalidFormat,
      "listener empty kind should have InvalidFormat kind"
    );
  }

  // =========================================================================
  // CR-009: extract_addresses is a free function (no duplication)
  // =========================================================================

  // =========================================================================
  // Access Log Config Tests (moved from access_log/config.rs)
  // =========================================================================

  #[test]
  fn test_parse_human_duration_ms() {
    let hd: HumanDuration = serde_yaml::from_str("500ms").unwrap();
    assert_eq!(hd.0, Duration::from_millis(500));
  }

  #[test]
  fn test_parse_human_duration_s() {
    let hd: HumanDuration = serde_yaml::from_str("1s").unwrap();
    assert_eq!(hd.0, Duration::from_secs(1));
  }

  #[test]
  fn test_parse_human_duration_m() {
    let hd: HumanDuration = serde_yaml::from_str("5m").unwrap();
    assert_eq!(hd.0, Duration::from_secs(300));
  }

  #[test]
  fn test_parse_human_duration_h() {
    let hd: HumanDuration = serde_yaml::from_str("1h").unwrap();
    assert_eq!(hd.0, Duration::from_secs(3600));
  }

  #[test]
  fn test_parse_human_duration_composite() {
    let hd: HumanDuration = serde_yaml::from_str("1h30m").unwrap();
    assert_eq!(hd.0, Duration::from_secs(3600 + 30 * 60));
  }

  #[test]
  fn test_parse_human_duration_lowercase_only() {
    let hd: HumanDuration = serde_yaml::from_str("1s").unwrap();
    assert_eq!(hd.0, Duration::from_secs(1));
    let result: Result<HumanDuration, _> = serde_yaml::from_str("1S");
    assert!(result.is_err(), "Uppercase units should not be supported");
  }

  #[test]
  fn test_parse_human_duration_invalid_unit() {
    let result: Result<HumanDuration, _> = serde_yaml::from_str("1x");
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_human_duration_no_number() {
    let result: Result<HumanDuration, _> = serde_yaml::from_str("ms");
    assert!(result.is_err());
  }

  #[test]
  fn test_log_format_default_is_text() {
    let fmt = LogFormat::default();
    assert!(matches!(fmt, LogFormat::Text));
  }

  #[test]
  fn test_log_format_deserialize_text() {
    let fmt: LogFormat = serde_yaml::from_str("text").unwrap();
    assert!(matches!(fmt, LogFormat::Text));
  }

  #[test]
  fn test_log_format_deserialize_json() {
    let fmt: LogFormat = serde_yaml::from_str("json").unwrap();
    assert!(matches!(fmt, LogFormat::Json));
  }

  #[test]
  fn test_access_log_config_defaults() {
    let config = AccessLogConfig::default();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "access.log");
    assert!(matches!(config.format, LogFormat::Text));
    assert_eq!(config.buffer.as_u64(), 32 * 1024);
    assert_eq!(config.flush.0, Duration::from_secs(1));
    assert_eq!(config.max_size.as_u64(), 200 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_full() {
    let yaml = r#"
enabled: true
path_prefix: "http_access.log"
format: json
buffer: 64KiB
flush: 3s
max_size: 100MiB
"#;
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "http_access.log");
    assert!(matches!(config.format, LogFormat::Json));
    assert_eq!(config.buffer.as_u64(), 64 * 1024);
    assert_eq!(config.flush.0, Duration::from_secs(3));
    assert_eq!(config.max_size.as_u64(), 100 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_partial() {
    let yaml = r#"
path_prefix: "custom.log"
format: json
"#;
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "custom.log");
    assert!(matches!(config.format, LogFormat::Json));
    assert_eq!(config.buffer.as_u64(), 32 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_empty() {
    let yaml = "{}";
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "access.log");
  }

  #[test]
  fn test_access_log_config_merge_override_all() {
    let base = AccessLogConfig::default();
    let override_config = AccessLogOverride {
      enabled: Some(false),
      path_prefix: Some("override.log".to_string()),
      format: Some(LogFormat::Json),
      buffer: Some(Byte::from_u64(64 * 1024)),
      flush: Some(HumanDuration(Duration::from_secs(5))),
      max_size: Some(Byte::from_u64(500 * 1024 * 1024)),
    };
    let merged = base.merge(&override_config);
    assert!(!merged.enabled);
    assert_eq!(merged.path_prefix, "override.log");
    assert!(matches!(merged.format, LogFormat::Json));
    assert_eq!(merged.buffer.as_u64(), 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(5));
    assert_eq!(merged.max_size.as_u64(), 500 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_merge_partial_override() {
    let base = AccessLogConfig {
      enabled: true,
      path_prefix: "base.log".to_string(),
      format: LogFormat::Text,
      buffer: Byte::from_u64(64 * 1024),
      flush: HumanDuration(Duration::from_secs(3)),
      max_size: Byte::from_u64(100 * 1024 * 1024),
    };
    let override_config = AccessLogOverride {
      enabled: None,
      path_prefix: Some("http_access.log".to_string()),
      format: None,
      buffer: None,
      flush: None,
      max_size: None,
    };
    let merged = base.merge(&override_config);
    assert_eq!(merged.path_prefix, "http_access.log");
    assert!(merged.enabled);
    assert!(matches!(merged.format, LogFormat::Text));
    assert_eq!(merged.buffer.as_u64(), 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(3));
    assert_eq!(merged.max_size.as_u64(), 100 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_merge_empty_override() {
    let base = AccessLogConfig {
      enabled: true,
      path_prefix: "base.log".to_string(),
      format: LogFormat::Json,
      buffer: Byte::from_u64(64 * 1024),
      flush: HumanDuration(Duration::from_secs(5)),
      max_size: Byte::from_u64(500 * 1024 * 1024),
    };
    let override_config = AccessLogOverride {
      enabled: None,
      path_prefix: None,
      format: None,
      buffer: None,
      flush: None,
      max_size: None,
    };
    let merged = base.merge(&override_config);
    assert!(merged.enabled);
    assert_eq!(merged.path_prefix, "base.log");
    assert!(matches!(merged.format, LogFormat::Json));
    assert_eq!(merged.buffer.as_u64(), 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(5));
    assert_eq!(merged.max_size.as_u64(), 500 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_override_deserialize_partial() {
    let yaml = r#"
path_prefix: "http_access.log"
format: json
"#;
    let override_config: AccessLogOverride =
      serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
      override_config.path_prefix,
      Some("http_access.log".to_string())
    );
    assert!(matches!(override_config.format, Some(LogFormat::Json)));
    assert!(override_config.enabled.is_none());
    assert!(override_config.buffer.is_none());
    assert!(override_config.flush.is_none());
    assert!(override_config.max_size.is_none());
  }

  #[test]
  fn test_access_log_override_deserialize_empty() {
    let yaml = "{}";
    let override_config: AccessLogOverride =
      serde_yaml::from_str(yaml).unwrap();
    assert!(override_config.enabled.is_none());
    assert!(override_config.path_prefix.is_none());
    assert!(override_config.format.is_none());
    assert!(override_config.buffer.is_none());
    assert!(override_config.flush.is_none());
    assert!(override_config.max_size.is_none());
  }

  #[test]
  fn test_access_log_config_validate_valid() {
    use crate::config_validator::{
      ConfigErrorCollector, validate_access_log_config,
    };
    let config = AccessLogConfig::default();
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(!collector.has_errors(), "Default config should be valid");
  }

  #[test]
  fn test_access_log_config_validate_buffer_too_small() {
    use crate::config_validator::{
      ConfigErrorCollector, validate_access_log_config,
    };
    let config = AccessLogConfig {
      buffer: Byte::from_u64(512), // Less than 1KB
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "access_log.buffer"
        && e.message.contains("at least 1KB")
    });
    assert!(found, "Should have buffer size validation error");
  }

  #[test]
  fn test_access_log_config_validate_max_size_too_small() {
    use crate::config_validator::{
      ConfigErrorCollector, validate_access_log_config,
    };
    let config = AccessLogConfig {
      max_size: Byte::from_u64(512 * 1024), // Less than 1MB
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "access_log.max_size"
        && e.message.contains("at least 1MB")
    });
    assert!(found, "Should have max_size validation error");
  }

  #[test]
  fn test_access_log_config_validate_flush_too_short() {
    use crate::config_validator::{
      ConfigErrorCollector, validate_access_log_config,
    };
    let config = AccessLogConfig {
      flush: HumanDuration(Duration::from_millis(50)), // Less than 100ms
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "access_log.flush"
        && e.message.contains("at least 100ms")
    });
    assert!(found, "Should have flush interval validation error");
  }

  #[test]
  fn test_access_log_config_validate_empty_path_prefix() {
    use crate::config_validator::{
      ConfigErrorCollector, validate_access_log_config,
    };
    let config = AccessLogConfig {
      path_prefix: String::new(),
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "access_log.path_prefix"
        && e.message.contains("cannot be empty")
    });
    assert!(found, "Should have empty path_prefix validation error");
  }
}
