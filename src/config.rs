use std::collections::HashSet;
use std::fs;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

use crate::config_validator::{
  ConfigErrorCollector, ConfigErrorKind, parse_kind,
};
use crate::listeners::ListenerBuilderSet;
use crate::plugin;
use crate::plugins::PluginBuilderSet;

/// Check if a string is a valid bcrypt hash format
///
/// Supports both PHC format and standard bcrypt format:
/// - PHC format: $bcrypt$v=98$r=<rounds>$<hash>
/// - Standard bcrypt format: $2a$12$<salt><hash>, $2b$12$<salt><hash>, etc.
///
/// Validates both format structure and hash content:
/// - Format structure must be correct
/// - Hash content must be non-empty and have valid length
fn is_valid_bcrypt_hash(hash: &str) -> bool {
  // Check for PHC format: $bcrypt$v=98$r=<rounds>$<hash>
  if hash.starts_with("$bcrypt$") {
    // Expected format: $bcrypt$v=98$r=12$<hash>
    let parts: Vec<&str> = hash.split('$').collect();
    // Should have at least 5 parts: "", "bcrypt", "v=98", "r=12", "<hash>"
    if parts.len() < 5 {
      return false;
    }
    // Check version part
    if !parts[2].starts_with("v=") {
      return false;
    }
    // Check rounds part
    if !parts[3].starts_with("r=") {
      return false;
    }
    // Parse rounds and check it's valid
    let rounds_str = &parts[3][2..];
    if let Ok(rounds) = rounds_str.parse::<u32>() {
      // bcrypt rounds should be between 4 and 31 (log2)
      if !(4..=31).contains(&rounds) {
        return false;
      }
    } else {
      return false;
    }
    // Validate hash content exists and has sufficient length
    // PHC format expects hash content after the 4th '$'
    // bcrypt produces 24 bytes (184 bits) of hash, base64 encoded to ~31 chars
    // We require at least 30 characters for meaningful hash content
    let hash_content = parts[4];
    if hash_content.is_empty() {
      return false;
    }
    // Hash content should be valid base64 with meaningful content
    hash_content.len() >= 30
  }
  // Check for standard bcrypt format: $2a$, $2b$, $2x$, $2y$
  else if hash.starts_with("$2a$")
    || hash.starts_with("$2b$")
    || hash.starts_with("$2x$")
    || hash.starts_with("$2y$")
  {
    // Expected format: $2a$12$<salt><hash>
    // Standard bcrypt: 22 chars salt + 31 chars hash = 53 chars total
    let parts: Vec<&str> = hash.split('$').collect();
    // Should have at least 4 parts: "", "2a", "12", "<salt><hash>"
    if parts.len() < 4 {
      return false;
    }
    // Check cost factor
    let cost = match parts[2].parse::<u32>() {
      Ok(c) => c,
      Err(_) => return false,
    };
    // bcrypt cost should be between 4 and 31
    if !(4..=31).contains(&cost) {
      return false;
    }
    // Validate hash content exists and has sufficient length
    // Standard bcrypt hash part should be 53 characters
    // (base64 encoded 128-bit salt + 184-bit hash without padding)
    // We require at least 50 characters for standard bcrypt hashes
    let hash_content = parts[3];
    if hash_content.is_empty() {
      return false;
    }
    // Standard bcrypt produces 22 chars salt + 31 chars hash = 53 chars total
    // We require at least 50 characters for a valid bcrypt hash
    hash_content.len() >= 50
  } else {
    false
  }
}

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
  pub kind: String,
  pub args: serde_yaml::Value,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Server {
  pub name: String,
  pub listeners: Vec<Listener>,
  pub service: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Layer {
  pub kind: String,
  // delegate the deserializition to layer factories
  pub args: serde_yaml::Value,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Service {
  pub name: String,
  pub kind: String,
  // delegate the deserializition to service factories.
  pub args: serde_yaml::Value,
  pub layers: Vec<Layer>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
  pub worker_threads: usize,
  pub log_directory: String,
  pub services: Vec<Service>,
  pub servers: Vec<Server>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      worker_threads: 1,
      log_directory: String::from("logs/"),
      services: vec![],
      servers: vec![],
    }
  }
}

impl Config {
  /// Parse config from a string
  pub fn parse_string(&mut self, s: &str) -> Result<()> {
    let de = serde_yaml::Deserializer::from_str(s);
    Deserialize::deserialize_in_place(de, self)
      .with_context(|| "parse config text failed".to_string())?;
    Ok(())
  }

  /// Read and parse config from a file
  fn parse_file(&mut self, path: &str) -> Result<()> {
    let s = fs::read_to_string(std::path::Path::new(path))
      .with_context(|| format!("read config file '{}'", path))?;
    self.parse_string(&s)?;
    Ok(())
  }

  /// Validate the configuration
  ///
  /// This method validates:
  /// - Kind format for all services and listeners
  /// - Plugin existence for all kinds
  /// - Service/listener builder existence in plugins
  /// - Service references in servers
  /// - Address parsing in listener args
  /// - Args parsing for all services and listeners
  pub fn validate(&self, collector: &mut ConfigErrorCollector) {
    // Collect all service names for reference validation
    let service_names: HashSet<&str> =
      self.services.iter().map(|s| s.name.as_str()).collect();

    // Validate services
    for (idx, service) in self.services.iter().enumerate() {
      let location = format!("services[{}]", idx);
      self.validate_service(service, &location, collector);
    }

    // Validate servers
    for (server_idx, server) in self.servers.iter().enumerate() {
      let server_location = format!("servers[{}]", server_idx);

      // Validate service reference
      if !server.service.is_empty()
        && !service_names.contains(server.service.as_str())
      {
        collector.add(
          format!("{}.service", server_location),
          format!("service '{}' not found", server.service),
          ConfigErrorKind::NotFound,
        );
      }

      // Validate listeners
      for (listener_idx, listener) in
        server.listeners.iter().enumerate()
      {
        let listener_location =
          format!("{}.listeners[{}]", server_location, listener_idx);
        self.validate_listener(listener, &listener_location, collector);
      }
    }
  }

  /// Validate a single service configuration
  fn validate_service(
    &self,
    service: &Service,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    let kind_location = format!("{}.kind", location);
    let args_location = format!("{}.args", location);

    // Validate kind format
    let (plugin_name, service_name) =
      match parse_kind(&service.kind, &kind_location) {
        Ok(parts) => parts,
        Err(e) => {
          collector.add(e.location, e.message, e.kind);
          return;
        }
      };

    // Check plugin existence
    let Some(plugin_builder) =
      PluginBuilderSet::global().plugin_builder(plugin_name)
    else {
      collector.add(
        kind_location,
        format!("plugin '{}' not found", plugin_name),
        ConfigErrorKind::NotFound,
      );
      return;
    };

    // Create plugin instance and check service builder
    let plugin = plugin_builder();
    let Some(builder) = plugin.service_builder(service_name) else {
      collector.add(
        kind_location,
        format!(
          "service builder '{}' not found in plugin '{}'",
          service_name, plugin_name
        ),
        ConfigErrorKind::NotFound,
      );
      return;
    };

    // Validate args by calling the builder
    // This will catch args parsing errors
    if let Err(e) = builder(service.args.clone()) {
      collector.add(
        args_location,
        e.to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }
  }

  /// Validate a single listener configuration
  fn validate_listener(
    &self,
    listener: &Listener,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    let kind_location = format!("{}.kind", location);
    let args_location = format!("{}.args", location);

    // Validate kind format
    let (_plugin_name, _listener_name) =
      match parse_kind(&listener.kind, &kind_location) {
        Ok(parts) => parts,
        Err(e) => {
          collector.add(e.location, e.message, e.kind);
          return;
        }
      };

    // Check listener builder existence directly using the full kind
    let Some(builder) =
      ListenerBuilderSet::global().listener_builder(&listener.kind)
    else {
      collector.add(
        kind_location,
        format!("listener builder '{}' not found", listener.kind),
        ConfigErrorKind::NotFound,
      );
      return;
    };

    // Validate args by calling the builder with a dummy service
    // This will catch args parsing errors
    let dummy_service = plugin::Service::new(DummyService {});
    if let Err(e) = builder(listener.args.clone(), dummy_service) {
      collector.add(
        args_location,
        e.to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }

    // Validate addresses in listener args if present
    self.validate_listener_addresses(
      &listener.args,
      location,
      collector,
    );

    // Validate HTTP/3 listener specific configuration
    if listener.kind == "http3.listener" {
      self.validate_http3_listener_args(
        &listener.args,
        location,
        collector,
      );
    }
  }

  /// Validate addresses in listener args
  fn validate_listener_addresses(
    &self,
    args: &serde_yaml::Value,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Check if args has an "addresses" field
    if let Some(addresses) = args.get("addresses")
      && let Some(addrs) = addresses.as_sequence()
    {
      for (addr_idx, addr) in addrs.iter().enumerate() {
        if let Some(addr_str) = addr.as_str()
          && addr_str.parse::<std::net::SocketAddr>().is_err()
        {
          collector.add(
            format!("{}.args.addresses[{}]", location, addr_idx),
            format!("invalid address '{}'", addr_str),
            ConfigErrorKind::InvalidAddress,
          );
        }
      }
    }
  }

  /// Validate HTTP/3 listener specific configuration
  ///
  /// Validates:
  /// - Address format
  /// - Certificate file existence and readability
  /// - Certificate format (PEM)
  /// - Private key file existence and readability
  /// - Private key format (PEM)
  /// - Certificate and private key match
  /// - QUIC parameters validity
  /// - Authentication configuration completeness
  /// - Password hash format for password authentication
  fn validate_http3_listener_args(
    &self,
    args: &serde_yaml::Value,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Validate address format
    if let Some(address) = args.get("address") {
      if let Some(addr_str) = address.as_str() {
        if addr_str.parse::<std::net::SocketAddr>().is_err() {
          collector.add(
            format!("{}.args.address", location),
            format!("invalid address '{}'", addr_str),
            ConfigErrorKind::InvalidAddress,
          );
        }
      }
    }

    // Validate certificate path and get content for matching check
    let cert_content = if let Some(cert_path) = args.get("cert_path") {
      if let Some(cert_path_str) = cert_path.as_str() {
        self.validate_certificate_file(
          cert_path_str,
          &format!("{}.args.cert_path", location),
          collector,
        )
      } else {
        None
      }
    } else {
      None
    };

    // Validate private key path and get content for matching check
    let key_content = if let Some(key_path) = args.get("key_path") {
      if let Some(key_path_str) = key_path.as_str() {
        self.validate_private_key_file(
          key_path_str,
          &format!("{}.args.key_path", location),
          collector,
        )
      } else {
        None
      }
    } else {
      None
    };

    // Validate certificate and private key match
    if let (Some(cert), Some(key)) = (&cert_content, &key_content) {
      self.validate_cert_key_match(
        cert,
        key,
        &format!("{}.args", location),
        collector,
      );
    }

    // Validate QUIC parameters
    if let Some(quic) = args.get("quic") {
      self.validate_quic_config(
        quic,
        &format!("{}.args.quic", location),
        collector,
      );
    }

    // Validate authentication configuration
    if let Some(auth) = args.get("auth") {
      self.validate_http3_auth_config(auth, location, collector);
    }
  }

  /// Validate certificate file
  /// Returns the file content if valid, None otherwise
  fn validate_certificate_file(
    &self,
    cert_path: &str,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) -> Option<String> {
    // Check file exists and is readable
    match fs::read_to_string(std::path::Path::new(cert_path)) {
      Ok(content) => {
        // Check PEM format
        if !content.contains("-----BEGIN CERTIFICATE-----")
          && !content.contains("-----BEGIN TRUSTED CERTIFICATE-----")
        {
          collector.add(
            location.to_string(),
            format!(
              "certificate file '{}' is not in PEM format",
              cert_path
            ),
            ConfigErrorKind::InvalidFormat,
          );
          None
        } else {
          Some(content)
        }
      }
      Err(e) => {
        collector.add(
          location.to_string(),
          format!(
            "certificate file '{}' cannot be read: {}",
            cert_path, e
          ),
          ConfigErrorKind::FileRead,
        );
        None
      }
    }
  }

  /// Validate private key file
  /// Returns the file content if valid, None otherwise
  fn validate_private_key_file(
    &self,
    key_path: &str,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) -> Option<String> {
    // Check file exists and is readable
    match fs::read_to_string(std::path::Path::new(key_path)) {
      Ok(content) => {
        // Check PEM format
        if !content.contains("-----BEGIN PRIVATE KEY-----")
          && !content.contains("-----BEGIN RSA PRIVATE KEY-----")
          && !content.contains("-----BEGIN EC PRIVATE KEY-----")
          && !content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        {
          collector.add(
            location.to_string(),
            format!(
              "private key file '{}' is not in PEM format",
              key_path
            ),
            ConfigErrorKind::InvalidFormat,
          );
          None
        } else {
          Some(content)
        }
      }
      Err(e) => {
        collector.add(
          location.to_string(),
          format!(
            "private key file '{}' cannot be read: {}",
            key_path, e
          ),
          ConfigErrorKind::FileRead,
        );
        None
      }
    }
  }

  /// Validate that certificate and private key match
  ///
  /// This method attempts to parse the certificate and private key
  /// and verifies that they form a valid key pair.
  fn validate_cert_key_match(
    &self,
    cert_content: &str,
    key_content: &str,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Try to parse the certificate chain
    let cert_chain: Vec<rustls::pki_types::CertificateDer> =
      rustls_pemfile::certs(&mut std::io::Cursor::new(cert_content))
        .filter_map(|r| r.ok())
        .collect();

    if cert_chain.is_empty() {
      collector.add(
        format!("{}.cert_path", location),
        "no valid certificates found in certificate file".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
      return;
    }

    // Try to parse the private key
    let private_key = rustls_pemfile::private_key(
      &mut std::io::Cursor::new(key_content),
    )
    .ok()
    .flatten();

    let Some(private_key) = private_key else {
      collector.add(
        format!("{}.key_path", location),
        "no valid private key found in key file".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
      return;
    };

    // Try to build a ServerConfig with the cert and key
    // This will fail if they don't match
    match rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(cert_chain, private_key)
    {
      Ok(_) => {
        // Certificate and key match - validation passed
      }
      Err(e) => {
        collector.add(
          location.to_string(),
          format!("certificate and private key do not match: {}", e),
          ConfigErrorKind::InvalidFormat,
        );
      }
    }
  }

  /// Validate QUIC configuration parameters
  ///
  /// Validates QUIC parameters and reports errors for invalid values.
  /// Invalid parameters will cause startup to fail.
  fn validate_quic_config(
    &self,
    quic: &serde_yaml::Value,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Validate max_concurrent_bidi_streams
    if let Some(v) = quic.get("max_concurrent_bidi_streams") {
      if let Some(n) = v.as_u64() {
        if n < 1 || n > 10000 {
          collector.add(
            format!("{}.max_concurrent_bidi_streams", location),
            format!("invalid value {}, expected range 1-10000", n),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
    }

    // Validate max_idle_timeout_ms
    if let Some(v) = quic.get("max_idle_timeout_ms") {
      if let Some(n) = v.as_u64() {
        if n == 0 {
          collector.add(
            format!("{}.max_idle_timeout_ms", location),
            "invalid value 0, expected value > 0".to_string(),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
    }

    // Validate initial_mtu
    if let Some(v) = quic.get("initial_mtu") {
      if let Some(n) = v.as_u64() {
        if n < 1200 || n > 9000 {
          collector.add(
            format!("{}.initial_mtu", location),
            format!("invalid value {}, expected range 1200-9000", n),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
    }

    // Validate send_window
    if let Some(v) = quic.get("send_window") {
      if let Some(n) = v.as_u64() {
        if n == 0 {
          collector.add(
            format!("{}.send_window", location),
            "invalid value 0, expected value > 0".to_string(),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
    }

    // Validate receive_window
    if let Some(v) = quic.get("receive_window") {
      if let Some(n) = v.as_u64() {
        if n == 0 {
          collector.add(
            format!("{}.receive_window", location),
            "invalid value 0, expected value > 0".to_string(),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
    }
  }

  /// Validate HTTP/3 authentication configuration
  fn validate_http3_auth_config(
    &self,
    auth: &serde_yaml::Value,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Get authentication type
    let auth_type = auth.get("type").and_then(|v| v.as_str());

    match auth_type {
      Some("password") => {
        // Password authentication: credentials must be present and non-empty
        if let Some(credentials) = auth.get("credentials") {
          if let Some(creds) = credentials.as_sequence() {
            if creds.is_empty() {
              collector.add(
                format!("{}.args.auth.credentials", location),
                "credentials cannot be empty for password authentication"
                  .to_string(),
                ConfigErrorKind::InvalidFormat,
              );
            }
            // Validate each credential
            for (idx, cred) in creds.iter().enumerate() {
              if let Some(cred_map) = cred.as_mapping() {
                // Check username
                if !cred_map.contains_key(&serde_yaml::Value::String(
                  "username".to_string(),
                )) {
                  collector.add(
                    format!(
                      "{}.args.auth.credentials[{}].username",
                      location, idx
                    ),
                    "username is required".to_string(),
                    ConfigErrorKind::MissingField,
                  );
                }
                // Check password_hash field exists
                if !cred_map.contains_key(&serde_yaml::Value::String(
                  "password_hash".to_string(),
                )) {
                  collector.add(
                    format!(
                      "{}.args.auth.credentials[{}].password_hash",
                      location, idx
                    ),
                    "password_hash is required".to_string(),
                    ConfigErrorKind::MissingField,
                  );
                } else if let Some(hash_value) =
                  cred_map.get(&serde_yaml::Value::String(
                    "password_hash".to_string(),
                  ))
                {
                  // Validate password hash format (bcrypt)
                  if let Some(hash_str) = hash_value.as_str() {
                    if !is_valid_bcrypt_hash(hash_str) {
                      collector.add(
                        format!(
                          "{}.args.auth.credentials[{}].password_hash",
                          location, idx
                        ),
                        format!(
                          "invalid bcrypt hash format, expected format \
                           like $2a$12$... or $bcrypt$v=98$r=12$..."
                        ),
                        ConfigErrorKind::InvalidFormat,
                      );
                    }
                  }
                }
              }
            }
          } else {
            collector.add(
              format!("{}.args.auth.credentials", location),
              "credentials must be an array".to_string(),
              ConfigErrorKind::TypeMismatch,
            );
          }
        } else {
          collector.add(
            format!("{}.args.auth.credentials", location),
            "credentials is required for password authentication"
              .to_string(),
            ConfigErrorKind::MissingField,
          );
        }
      }
      Some("tls_client_cert") => {
        // TLS client cert authentication: client_ca_path must be present
        if let Some(client_ca_path) = auth.get("client_ca_path") {
          if let Some(ca_path_str) = client_ca_path.as_str() {
            // Validate client CA file
            self.validate_client_ca_file(
              ca_path_str,
              &format!("{}.args.auth.client_ca_path", location),
              collector,
            );
          }
        } else {
          collector.add(
            format!("{}.args.auth.client_ca_path", location),
            "client_ca_path is required for tls_client_cert authentication"
              .to_string(),
            ConfigErrorKind::MissingField,
          );
        }
      }
      Some(other) => {
        collector.add(
          format!("{}.args.auth.type", location),
          format!("invalid authentication type '{}'", other),
          ConfigErrorKind::InvalidFormat,
        );
      }
      None => {
        collector.add(
          format!("{}.args.auth.type", location),
          "authentication type is required".to_string(),
          ConfigErrorKind::MissingField,
        );
      }
    }
  }

  /// Validate client CA certificate file
  fn validate_client_ca_file(
    &self,
    ca_path: &str,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Check file exists and is readable
    match fs::read_to_string(std::path::Path::new(ca_path)) {
      Ok(content) => {
        // Check PEM format
        if !content.contains("-----BEGIN CERTIFICATE-----")
          && !content.contains("-----BEGIN TRUSTED CERTIFICATE-----")
        {
          collector.add(
            location.to_string(),
            format!(
              "client CA file '{}' is not in PEM format",
              ca_path
            ),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
      Err(e) => {
        collector.add(
          location.to_string(),
          format!("client CA file '{}' cannot be read: {}", ca_path, e),
          ConfigErrorKind::FileRead,
        );
      }
    }
  }

  /// Load and validate configuration from a file
  ///
  /// Returns the config if valid, otherwise prints errors and exits.
  pub fn load_and_validate(path: &str) -> Config {
    let mut collector = ConfigErrorCollector::new();

    // Try to read and parse the file
    let mut config: Config = Default::default();
    match config.parse_file(path) {
      Ok(()) => {}
      Err(e) => {
        // Check if it's a file read error
        let err_str = e.to_string();
        if err_str.contains("read config file") {
          // File read error - print friendly message and exit
          eprintln!(
            "Error: Cannot read config file '{}': {}",
            path,
            err_str
              .replace(&format!("read config file '{}': ", path), "")
          );
          std::process::exit(1);
        } else {
          // YAML parse error
          collector.add("config", err_str, ConfigErrorKind::YamlParse);
          collector.report_and_exit();
        }
      }
    }

    // Validate the parsed config
    config.validate(&mut collector);

    // If there are validation errors, report and exit
    if collector.has_errors() {
      collector.report_and_exit();
    }

    config
  }

  pub fn global() -> &'static LazyLock<Config> {
    static CONFIG: LazyLock<Config> = LazyLock::new(|| {
      Config::load_and_validate(&CmdOpt::global().config_file)
    });
    &CONFIG
  }
}

/// A dummy service used for validating listener args
/// This service does nothing and is only used to pass to
/// listener builders during validation
#[derive(Clone)]
struct DummyService {}

impl tower::Service<plugin::Request> for DummyService {
  type Error = anyhow::Error;
  type Future = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<plugin::Response>>>,
  >;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    _cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<()>> {
    std::task::Poll::Ready(Ok(()))
  }

  fn call(&mut self, _req: plugin::Request) -> Self::Future {
    Box::pin(async {
      anyhow::bail!("DummyService should not be called")
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // Initialize CryptoProvider for tests that involve TLS/QUIC
  static CRYPTO_PROVIDER_INIT: std::sync::Once = std::sync::Once::new();

  fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
      rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    });
  }

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
  fn test_dummy_service_poll_ready() {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use tower::Service;

    // Create a no-op waker
    fn no_op_clone(_: *const ()) -> RawWaker {
      no_op_raw_waker()
    }
    fn no_op(_: *const ()) {}
    fn no_op_raw_waker() -> RawWaker {
      static VTABLE: RawWakerVTable =
        RawWakerVTable::new(no_op_clone, no_op, no_op, no_op);
      RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(no_op_raw_waker()) };
    let mut cx = Context::from_waker(&waker);

    let mut service = DummyService {};
    match service.poll_ready(&mut cx) {
      Poll::Ready(Ok(())) => {}
      _ => panic!("Expected Poll::Ready(Ok(()))"),
    }
  }

  #[test]
  fn test_dummy_service_call() {
    use http_body_util::BodyExt;
    use http_body_util::combinators::UnsyncBoxBody;
    use tower::Service;

    let mut service = DummyService {};
    let body: UnsyncBoxBody<bytes::Bytes, anyhow::Error> =
      http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
        .boxed_unsync();
    let request = http::Request::builder()
      .method("GET")
      .uri("/")
      .body(body)
      .unwrap();

    let future = service.call(request);
    // The future should complete with an error
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(future);
    assert!(result.is_err());
    assert!(
      result
        .unwrap_err()
        .to_string()
        .contains("DummyService should not be called")
    );
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
  fn test_validate_empty_config() {
    let config = Config::default();
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_valid_service() {
    let config = Config {
      services: vec![Service {
        name: "test_echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_kind_format() {
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "invalidkind".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
  }

  #[test]
  fn test_validate_nonexistent_plugin() {
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "nonexistent.service".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(errors[0].message.contains("plugin"));
  }

  #[test]
  fn test_validate_nonexistent_service_builder() {
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "echo.nonexistent".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(errors[0].message.contains("service builder"));
  }

  #[test]
  fn test_validate_valid_listener() {
    let args = serde_yaml::from_str(
      r#"{addresses: ["127.0.0.1:8080"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_listener_kind() {
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          kind: "invalid".to_string(),
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
  }

  #[test]
  fn test_validate_nonexistent_listener_builder() {
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          kind: "hyper.nonexistent".to_string(),
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(
      errors[0]
        .message
        .contains("listener builder 'hyper.nonexistent' not found")
    );
  }

  #[test]
  fn test_validate_service_reference_not_found() {
    let config = Config {
      services: vec![],
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(
      errors[0].message.contains("service 'nonexistent' not found")
    );
  }

  #[test]
  fn test_validate_service_reference_found() {
    let config = Config {
      services: vec![Service {
        name: "existing".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "existing".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_valid_address() {
    let args = serde_yaml::from_str(
      r#"{addresses: ["127.0.0.1:8080"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_address() {
    let args = serde_yaml::from_str(
      r#"{addresses: ["invalid:address"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_multiple_invalid_addresses() {
    let args = serde_yaml::from_str(
      r#"{addresses: ["invalid1", "127.0.0.1:8080", "invalid2"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
    assert_eq!(errors[1].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_addresses_non_string() {
    // Non-string items in addresses array cause args parsing error
    // because HyperListenerArgs.addresses is Vec<String>
    let args = serde_yaml::from_str(
      r#"{addresses: [123, 456], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // This is now an args parsing error
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
  }

  #[test]
  fn test_validate_multiple_services_and_listeners() {
    let listener_args: serde_yaml::Value = serde_yaml::from_str(
      r#"{addresses: ["127.0.0.1:8080"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      services: vec![
        Service {
          name: "echo".to_string(),
          kind: "echo.echo".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
        Service {
          name: "connect".to_string(),
          kind: "connect_tcp.connect_tcp".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
      ],
      servers: vec![
        Server {
          name: "server1".to_string(),
          listeners: vec![Listener {
            kind: "hyper.listener".to_string(),
            args: listener_args.clone(),
          }],
          service: "echo".to_string(),
        },
        Server {
          name: "server2".to_string(),
          listeners: vec![Listener {
            kind: "hyper.listener".to_string(),
            args: listener_args,
          }],
          service: "connect".to_string(),
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_multiple_errors() {
    let config = Config {
      services: vec![
        Service {
          name: "test".to_string(),
          kind: "invalid.kind".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
        Service {
          name: "test2".to_string(),
          kind: "echo.nonexistent".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
      ],
      servers: vec![Server {
        name: "server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 3);
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
    assert!(service.kind.is_empty());
    assert!(service.layers.is_empty());
  }

  #[test]
  fn test_listener_default() {
    let listener = Listener::default();
    assert!(listener.kind.is_empty());
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
    assert!(layer.kind.is_empty());
  }

  #[test]
  fn test_config_clone() {
    let config = Config {
      worker_threads: 2,
      log_directory: "test/".to_string(),
      services: vec![],
      servers: vec![],
    };
    let cloned = config.clone();
    assert_eq!(cloned.worker_threads, 2);
  }

  #[test]
  fn test_validate_listener_plugin_not_found() {
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "nonexistent.listener".to_string(),
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert!(
      errors[0]
        .message
        .contains("listener builder 'nonexistent.listener' not found")
    );
  }

  #[test]
  fn test_validate_empty_service_name() {
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![],
        service: "".to_string(), // empty service name should be allowed
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_addresses_missing_field() {
    // Missing required field 'addresses' causes args parsing error
    let args = serde_yaml::from_str(
      r#"{other_field: "value", protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // This is now an args parsing error (missing required field)
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(errors[0].message.contains("addresses"));
  }

  #[test]
  fn test_validate_addresses_empty_array() {
    let args = serde_yaml::from_str(
      r#"{addresses: [], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_service_args_parsing_error() {
    // connect_tcp.connect_tcp expects () as args, not a map
    let args = serde_yaml::from_str(r#"{invalid: "field"}"#).unwrap();
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "connect_tcp.connect_tcp".to_string(),
        args,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(errors[0].location.contains("args"));
  }

  #[test]
  fn test_validate_listener_args_parsing_error() {
    // Missing required field 'addresses' for hyper.listener
    let args = serde_yaml::from_str(r#"{protocols: []}"#).unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(errors[0].message.contains("addresses"));
  }

  #[test]
  fn test_load_and_validate_file_not_found() {
    // Create a temp file to ensure we have a unique non-existent path
    let temp_dir = get_temp_dir();
    let non_existent_path =
      temp_dir.join("neoproxy_test_nonexistent_config_12345.yaml");
    // Remove if it somehow exists
    let _ = std::fs::remove_file(&non_existent_path);

    // This test cannot use load_and_validate directly because it exits
    // Instead, we test parse_file with a non-existent path
    let mut config = Config::default();
    let result = config.parse_file(non_existent_path.to_str().unwrap());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("read config file"));
  }

  #[test]
  fn test_load_and_validate_valid_config() {
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
      - kind: "hyper.listener"
        args:
          addresses: ["127.0.0.1:8080"]
          protocols: []
          hostnames: []
    service: "echo_svc"
"#;
    std::fs::write(&temp_path, config_content).unwrap();

    let config = Config::load_and_validate(temp_path.to_str().unwrap());
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.servers.len(), 1);

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
  // HTTP/3 Listener Configuration Validation Tests
  // =========================================================================

  /// Generate real test certificates for HTTP/3 listener tests
  /// Uses rcgen to generate valid self-signed certificates.
  /// Each test generates unique certificates to avoid race conditions.
  fn generate_test_certificates()
  -> (std::path::PathBuf, std::path::PathBuf) {
    use std::collections::hash_map::DefaultHasher;
    use std::fs::Permissions;
    use std::hash::{Hash, Hasher};
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = get_temp_dir();

    // Generate unique filename based on process ID and thread ID
    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let unique_id = hasher.finish();

    let cert_path = temp_dir
      .join(format!("neoproxy_http3_test_cert_{}.pem", unique_id));
    let key_path = temp_dir
      .join(format!("neoproxy_http3_test_key_{}.pem", unique_id));

    // Generate real certificates using rcgen
    let subject_alt_names =
      vec!["localhost".to_string(), "127.0.0.1".to_string()];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
      .expect("Failed to generate certificate");

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    std::fs::write(&cert_path, cert_pem).expect("Failed to write cert");
    std::fs::write(&key_path, key_pem).expect("Failed to write key");

    // Set secure permissions for the private key (0o600 = rw-------)
    std::fs::set_permissions(&key_path, Permissions::from_mode(0o600))
      .expect("Failed to set key permissions");

    (cert_path, key_path)
  }

  /// Generate a real client CA certificate for TLS client cert auth tests
  /// Uses rcgen to generate a valid certificate.
  /// Each test generates unique certificates to avoid race conditions.
  fn generate_test_client_ca_certificate() -> std::path::PathBuf {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let temp_dir = get_temp_dir();

    // Generate unique filename based on process ID and thread ID
    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let unique_id = hasher.finish();

    let ca_path = temp_dir
      .join(format!("neoproxy_http3_test_client_ca_{}.pem", unique_id));

    // Generate a certificate using rcgen (same as server cert, just for testing)
    // The config validation only checks if the file exists and is valid PEM format
    let subject_alt_names =
      vec!["localhost".to_string(), "127.0.0.1".to_string()];

    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
      .expect("Failed to generate CA certificate");

    let ca_pem = cert.cert.pem();

    std::fs::write(&ca_path, ca_pem).expect("Failed to write CA cert");

    ca_path
  }

  #[test]
  fn test_validate_http3_listener_valid_config() {
    ensure_crypto_provider();

    // Use real certificates generated by openssl
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    // Cleanup
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // No address validation errors (address format is valid)
    // Certificate and key format validation passed
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_http3_listener_invalid_address() {
    let temp_dir = get_temp_dir();
    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "invalid-address",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      temp_dir.join("cert.pem").to_str().unwrap(),
      temp_dir.join("key.pem").to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let address_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("address"))
      .collect();
    assert!(!address_errors.is_empty());
    assert_eq!(address_errors[0].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_http3_listener_cert_not_found() {
    let temp_dir = get_temp_dir();
    let non_existent_cert =
      temp_dir.join("non_existent_cert_12345.pem");
    let _ = std::fs::remove_file(&non_existent_cert);

    let key_path = temp_dir.join("neoproxy_test_key2.pem");
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      non_existent_cert.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let cert_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("cert_path"))
      .collect();
    assert!(!cert_errors.is_empty());
    assert_eq!(cert_errors[0].kind, ConfigErrorKind::FileRead);
  }

  #[test]
  fn test_validate_http3_listener_cert_not_pem() {
    ensure_crypto_provider();
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_invalid_cert.pem");
    let key_path = temp_dir.join("neoproxy_test_key3.pem");

    // Write invalid cert (not PEM format)
    std::fs::write(&cert_path, "not a pem certificate").unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let cert_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("cert_path"))
      .collect();
    assert!(!cert_errors.is_empty());
    assert_eq!(cert_errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(cert_errors[0].message.contains("not in PEM format"));
  }

  #[test]
  fn test_validate_http3_listener_key_not_found() {
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert4.pem");
    let non_existent_key = temp_dir.join("non_existent_key_12345.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let _ = std::fs::remove_file(&non_existent_key);

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      non_existent_key.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let key_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("key_path"))
      .collect();
    assert!(!key_errors.is_empty());
    assert_eq!(key_errors[0].kind, ConfigErrorKind::FileRead);
  }

  #[test]
  fn test_validate_http3_listener_key_not_pem() {
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert5.pem");
    let key_path = temp_dir.join("neoproxy_test_invalid_key.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(&key_path, "not a pem key").unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let key_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("key_path"))
      .collect();
    assert!(!key_errors.is_empty());
    assert_eq!(key_errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(key_errors[0].message.contains("not in PEM format"));
  }

  #[test]
  fn test_validate_http3_listener_rsa_private_key() {
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_rsa.pem");
    let key_path = temp_dir.join("neoproxy_test_key_rsa.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // RSA PRIVATE KEY format should be accepted
    let key_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("key_path"))
      .collect();
    assert!(key_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_ec_private_key() {
    ensure_crypto_provider();
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_ec.pem");
    let key_path = temp_dir.join("neoproxy_test_key_ec.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // EC PRIVATE KEY format should be accepted
    let key_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("key_path"))
      .collect();
    assert!(key_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_encrypted_private_key() {
    // This test verifies that ENCRYPTED PRIVATE KEY format is accepted
    // The test uses dummy data, so cert/key matching will fail,
    // but we only check that there's no key format error
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_enc.pem");
    let key_path = temp_dir.join("neoproxy_test_key_enc.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\ntest\n-----END ENCRYPTED PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // ENCRYPTED PRIVATE KEY format should be accepted
    // We check that there's no "not in PEM format" error for the key
    let key_format_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| {
        e.location.contains("key_path")
          && e.message.contains("not in PEM format")
      })
      .collect();
    assert!(key_format_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_auth_password_valid() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1",
        "password_hash": "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Password auth with valid credentials should pass
    let auth_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("auth"))
      .collect();
    assert!(auth_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_auth_password_missing_credentials() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password"
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let cred_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("credentials"))
      .collect();
    assert!(!cred_errors.is_empty());
    assert_eq!(cred_errors[0].kind, ConfigErrorKind::MissingField);
  }

  #[test]
  fn test_validate_http3_listener_auth_password_empty_credentials() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": []
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let cred_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("credentials"))
      .collect();
    assert!(!cred_errors.is_empty());
    assert_eq!(cred_errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(cred_errors[0].message.contains("cannot be empty"));
  }

  #[test]
  fn test_validate_http3_listener_auth_password_missing_username() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "password_hash": "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let username_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("username"))
      .collect();
    assert!(!username_errors.is_empty());
    assert_eq!(username_errors[0].kind, ConfigErrorKind::MissingField);
  }

  #[test]
  fn test_validate_http3_listener_auth_password_missing_password_hash()
  {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let hash_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("password_hash"))
      .collect();
    assert!(!hash_errors.is_empty());
    assert_eq!(hash_errors[0].kind, ConfigErrorKind::MissingField);
  }

  #[test]
  fn test_validate_http3_listener_auth_tls_client_cert_valid() {
    ensure_crypto_provider();

    // Use real certificates for proper validation
    let (cert_path, key_path) = generate_test_certificates();
    let ca_path = generate_test_client_ca_certificate();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "tls_client_cert",
    "client_ca_path": "{}"
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      ca_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&ca_path);

    // TLS client cert auth with valid CA should pass
    let auth_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("auth"))
      .collect();
    assert!(auth_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_auth_tls_client_cert_missing_ca() {
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_tls2.pem");
    let key_path = temp_dir.join("neoproxy_test_key_tls2.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "tls_client_cert"
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let ca_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("client_ca_path"))
      .collect();
    assert!(!ca_errors.is_empty());
    assert_eq!(ca_errors[0].kind, ConfigErrorKind::MissingField);
  }

  #[test]
  fn test_validate_http3_listener_auth_tls_client_cert_ca_not_found() {
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_tls3.pem");
    let key_path = temp_dir.join("neoproxy_test_key_tls3.pem");
    let non_existent_ca = temp_dir.join("non_existent_ca_12345.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let _ = std::fs::remove_file(&non_existent_ca);

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "tls_client_cert",
    "client_ca_path": "{}"
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      non_existent_ca.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let ca_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("client_ca_path"))
      .collect();
    assert!(!ca_errors.is_empty());
    assert_eq!(ca_errors[0].kind, ConfigErrorKind::FileRead);
  }

  #[test]
  fn test_validate_http3_listener_auth_tls_client_cert_ca_not_pem() {
    ensure_crypto_provider();
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_tls4.pem");
    let key_path = temp_dir.join("neoproxy_test_key_tls4.pem");
    let ca_path = temp_dir.join("neoproxy_test_invalid_ca.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(&ca_path, "not a pem certificate").unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "tls_client_cert",
    "client_ca_path": "{}"
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap(),
      ca_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&ca_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let ca_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("client_ca_path"))
      .collect();
    assert!(!ca_errors.is_empty());
    assert_eq!(ca_errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(ca_errors[0].message.contains("not in PEM format"));
  }

  #[test]
  fn test_validate_http3_listener_auth_invalid_type() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "invalid_type"
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let type_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("auth.type"))
      .collect();
    assert!(!type_errors.is_empty());
    assert_eq!(type_errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(
      type_errors[0].message.contains("invalid authentication type")
    );
  }

  #[test]
  fn test_validate_http3_listener_auth_missing_type() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let type_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("auth.type"))
      .collect();
    assert!(!type_errors.is_empty());
    assert_eq!(type_errors[0].kind, ConfigErrorKind::MissingField);
  }

  #[test]
  fn test_validate_http3_listener_auth_credentials_not_array() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": "not_an_array"
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    let errors = collector.errors();
    let cred_errors: Vec<_> = errors
      .iter()
      .filter(|e| e.location.contains("credentials"))
      .collect();
    assert!(!cred_errors.is_empty());
    assert_eq!(cred_errors[0].kind, ConfigErrorKind::TypeMismatch);
  }

  #[test]
  fn test_validate_http3_listener_multiple_credentials() {
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_multi.pem");
    let key_path = temp_dir.join("neoproxy_test_key_multi.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1",
        "password_hash": "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
      }},
      {{
        "username": "user2",
        "password_hash": "$2b$12$VoH3H6wXNGx9xLxJzXzYzOzX9z9z9z9z9z9z9z9z9z9z9z9z9z9z9"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Multiple credentials should be valid
    let auth_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("auth"))
      .collect();
    assert!(auth_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_trusted_certificate() {
    // This test verifies that TRUSTED CERTIFICATE format is accepted
    // The test uses dummy data, so cert/key matching will fail,
    // but we only check that there's no cert format error
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_trusted.pem");
    let key_path = temp_dir.join("neoproxy_test_key_trusted.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN TRUSTED CERTIFICATE-----\ntest\n-----END TRUSTED CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // TRUSTED CERTIFICATE format should be accepted
    // We check that there's no "not in PEM format" error for the cert
    let cert_format_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| {
        e.location.contains("cert_path")
          && e.message.contains("not in PEM format")
      })
      .collect();
    assert!(cert_format_errors.is_empty());
  }

  // =========================================================================
  // Certificate and Private Key Matching Validation Tests
  // =========================================================================

  #[test]
  fn test_validate_cert_key_match_valid() {
    ensure_crypto_provider();

    // Use real certificates for cert/key matching validation
    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Valid cert/key pair should pass with no errors
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_cert_key_mismatch() {
    ensure_crypto_provider();

    // Generate two different cert/key pairs
    let (cert_path1, key_path1) = generate_test_certificates();

    // Create a different private key
    let temp_dir = get_temp_dir();
    let key_path2 = temp_dir.join("neoproxy_test_key_mismatch.pem");

    // Generate a different key using openssl
    let output = std::process::Command::new("openssl")
      .args(["genrsa", "2048"])
      .output();

    if let Ok(output) = output {
      std::fs::write(&key_path2, &output.stdout).unwrap();

      let args = serde_yaml::from_str(&format!(
        r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
        cert_path1.to_str().unwrap(),
        key_path2.to_str().unwrap()
      ))
      .unwrap();

      let config = Config {
        servers: vec![Server {
          name: "test".to_string(),
          listeners: vec![Listener {
            kind: "http3.listener".to_string(),
            args,
          }],
          service: "".to_string(),
        }],
        ..Default::default()
      };
      let mut collector = ConfigErrorCollector::new();
      config.validate(&mut collector);

      let _ = std::fs::remove_file(&cert_path1);
      let _ = std::fs::remove_file(&key_path1);
      let _ = std::fs::remove_file(&key_path2);

      // Mismatched cert/key should produce an error
      assert!(collector.has_errors());
      let errors = collector.errors();
      let match_errors: Vec<_> = errors
        .iter()
        .filter(|e| {
          e.message.contains("certificate and private key do not match")
        })
        .collect();
      assert!(!match_errors.is_empty());
    } else {
      // openssl not available, skip the test
      let _ = std::fs::remove_file(&cert_path1);
      let _ = std::fs::remove_file(&key_path1);
    }
  }

  #[test]
  fn test_validate_cert_no_valid_certs() {
    ensure_crypto_provider();
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_no_valid.pem");
    let key_path = temp_dir.join("neoproxy_test_key_no_valid.pem");

    // Write invalid cert content (valid PEM markers but no actual certs)
    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    // The error message could be about no valid certs or cert/key mismatch
    let errors = collector.errors();
    let cert_errors: Vec<_> = errors
      .iter()
      .filter(|e| {
        e.message.contains("no valid certificates")
          || e
            .message
            .contains("certificate and private key do not match")
      })
      .collect();
    assert!(!cert_errors.is_empty());
  }

  #[test]
  fn test_validate_key_no_valid_key() {
    ensure_crypto_provider();
    let temp_dir = get_temp_dir();
    let cert_path = temp_dir.join("neoproxy_test_cert_no_key.pem");
    let key_path = temp_dir.join("neoproxy_test_key_no_key.pem");

    std::fs::write(
      &cert_path,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    // Write invalid key content (valid PEM markers but no actual key)
    std::fs::write(
      &key_path,
      "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}"
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert!(collector.has_errors());
    // The error message could be about no valid key or cert/key mismatch
    let errors = collector.errors();
    let key_errors: Vec<_> = errors
      .iter()
      .filter(|e| {
        e.message.contains("no valid private key")
          || e
            .message
            .contains("certificate and private key do not match")
      })
      .collect();
    assert!(!key_errors.is_empty());
  }

  // =========================================================================
  // Password Hash Format Validation Tests
  // =========================================================================

  #[test]
  fn test_validate_password_hash_valid_bcrypt_2a() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1",
        "password_hash": "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Valid bcrypt hash format should pass
    let hash_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| {
        e.location.contains("password_hash")
          && e.message.contains("bcrypt")
      })
      .collect();
    assert!(hash_errors.is_empty());
  }

  #[test]
  fn test_validate_password_hash_valid_bcrypt_2b() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1",
        "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Valid bcrypt hash format should pass
    let hash_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| {
        e.location.contains("password_hash")
          && e.message.contains("bcrypt")
      })
      .collect();
    assert!(hash_errors.is_empty());
  }

  #[test]
  fn test_validate_password_hash_valid_phc_format() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1",
        "password_hash": "$bcrypt$v=98$r=12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Valid PHC format should pass
    let hash_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| {
        e.location.contains("password_hash")
          && e.message.contains("bcrypt")
      })
      .collect();
    assert!(hash_errors.is_empty());
  }

  #[test]
  fn test_validate_password_hash_invalid_format() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1",
        "password_hash": "invalid_hash_format"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid hash format should produce error
    assert!(collector.has_errors());
    let errors = collector.errors();
    let hash_errors: Vec<_> = errors
      .iter()
      .filter(|e| {
        e.location.contains("password_hash")
          && e.message.contains("bcrypt")
      })
      .collect();
    assert!(!hash_errors.is_empty());
  }

  #[test]
  fn test_validate_password_hash_invalid_cost() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    // bcrypt cost must be between 4 and 31
    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "auth": {{
    "type": "password",
    "credentials": [
      {{
        "username": "user1",
        "password_hash": "$2a$99$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8"
      }}
    ]
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid cost should produce error
    assert!(collector.has_errors());
    let errors = collector.errors();
    let hash_errors: Vec<_> = errors
      .iter()
      .filter(|e| {
        e.location.contains("password_hash")
          && e.message.contains("bcrypt")
      })
      .collect();
    assert!(!hash_errors.is_empty());
  }

  // =========================================================================
  // QUIC Parameter Validation Tests
  // =========================================================================

  #[test]
  fn test_validate_quic_params_valid() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "max_concurrent_bidi_streams": 100,
    "max_idle_timeout_ms": 30000,
    "initial_mtu": 1200,
    "send_window": 10485760,
    "receive_window": 10485760
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Valid QUIC params should not produce errors
    let quic_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("quic"))
      .collect();
    assert!(quic_errors.is_empty());
  }

  #[test]
  fn test_validate_quic_params_invalid_max_concurrent_streams_low() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "max_concurrent_bidi_streams": 0
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid QUIC parameter should add error at config validation time
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(
      errors
        .iter()
        .any(|e| e.location.contains("max_concurrent_bidi_streams"))
    );
  }

  #[test]
  fn test_validate_quic_params_invalid_max_concurrent_streams_high() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "max_concurrent_bidi_streams": 20000
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid QUIC parameter should add error at config validation time
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(
      errors
        .iter()
        .any(|e| e.location.contains("max_concurrent_bidi_streams"))
    );
  }

  #[test]
  fn test_validate_quic_params_invalid_max_idle_timeout() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "max_idle_timeout_ms": 0
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid QUIC parameter should add error at config validation time
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(
      errors.iter().any(|e| e.location.contains("max_idle_timeout_ms"))
    );
  }

  #[test]
  fn test_validate_quic_params_invalid_initial_mtu_low() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "initial_mtu": 1000
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid QUIC parameter should add error at config validation time
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(errors.iter().any(|e| e.location.contains("initial_mtu")));
  }

  #[test]
  fn test_validate_quic_params_invalid_initial_mtu_high() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "initial_mtu": 10000
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid QUIC parameter should add error at config validation time
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(errors.iter().any(|e| e.location.contains("initial_mtu")));
  }

  #[test]
  fn test_validate_quic_params_invalid_send_window() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "send_window": 0
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid QUIC parameter should add error at config validation time
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(errors.iter().any(|e| e.location.contains("send_window")));
  }

  #[test]
  fn test_validate_quic_params_invalid_receive_window() {
    ensure_crypto_provider();

    let (cert_path, key_path) = generate_test_certificates();

    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": "{}",
  "quic": {{
    "receive_window": 0
  }}
}}"#,
      cert_path.to_str().unwrap(),
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    // Invalid QUIC parameter should add error at config validation time
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(
      errors.iter().any(|e| e.location.contains("receive_window"))
    );
  }

  // =========================================================================
  // is_valid_bcrypt_hash Function Tests
  // =========================================================================

  #[test]
  fn test_is_valid_bcrypt_hash_2a_format() {
    assert!(is_valid_bcrypt_hash(
      "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_2b_format() {
    assert!(is_valid_bcrypt_hash(
      "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_2x_format() {
    assert!(is_valid_bcrypt_hash(
      "$2x$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_2y_format() {
    assert!(is_valid_bcrypt_hash(
      "$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_format() {
    assert!(is_valid_bcrypt_hash(
      "$bcrypt$v=98$r=12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_invalid_format() {
    assert!(!is_valid_bcrypt_hash("invalid_hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_invalid_cost_too_low() {
    assert!(!is_valid_bcrypt_hash(
      "$2a$03$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_invalid_cost_too_high() {
    assert!(!is_valid_bcrypt_hash(
      "$2a$32$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYA/1IbCQ5Gu"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_missing_hash_part() {
    // "$2a$12$" has 4 parts after splitting: "", "2a", "12", ""
    // The hash content (parts[3]) is empty string
    // This should return false because there's no actual hash content
    let result = is_valid_bcrypt_hash("$2a$12$");
    assert!(!result);
  }

  #[test]
  fn test_is_valid_bcrypt_hash_missing_cost() {
    // "$2a$" has only 2 parts after splitting: "", "2a"
    // This should return false
    assert!(!is_valid_bcrypt_hash("$2a$"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_missing_version() {
    assert!(!is_valid_bcrypt_hash("$bcrypt$r=12$hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_missing_rounds() {
    assert!(!is_valid_bcrypt_hash("$bcrypt$v=98$hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_invalid_rounds() {
    assert!(!is_valid_bcrypt_hash(
      "$bcrypt$v=98$r=abc$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_invalid_cost_non_numeric() {
    // Non-numeric cost should return false
    assert!(!is_valid_bcrypt_hash("$2a$ab$hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_invalid_version() {
    // Wrong version format should return false
    assert!(!is_valid_bcrypt_hash("$bcrypt$x=98$r=12$hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_invalid_rounds_format() {
    // Rounds part doesn't start with "r=" should return false
    // This covers the case where parts[3] exists but doesn't start with "r="
    assert!(!is_valid_bcrypt_hash("$bcrypt$v=98$x=12$hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_empty_string() {
    assert!(!is_valid_bcrypt_hash(""));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_wrong_prefix() {
    assert!(!is_valid_bcrypt_hash("$2c$12$hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_rounds_out_of_range_low() {
    // PHC format with rounds below valid range (4-31)
    // This tests line 47: return false for rounds out of range
    assert!(!is_valid_bcrypt_hash(
      "$bcrypt$v=98$r=3$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_rounds_out_of_range_high() {
    // PHC format with rounds above valid range (4-31)
    // This tests line 47: return false for rounds out of range
    assert!(!is_valid_bcrypt_hash(
      "$bcrypt$v=98$r=32$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8"
    ));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_hash_too_short() {
    // PHC format with hash content too short (< 30 chars)
    // This tests line 58: return false for short hash content
    assert!(!is_valid_bcrypt_hash("$bcrypt$v=98$r=12$short_hash"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_empty_hash() {
    // PHC format with empty hash content
    // This tests line 58: return false for empty hash content
    assert!(!is_valid_bcrypt_hash("$bcrypt$v=98$r=12$"));
  }

  #[test]
  fn test_is_valid_bcrypt_hash_phc_insufficient_parts() {
    // PHC format with only 4 parts (missing hash content)
    assert!(!is_valid_bcrypt_hash("$bcrypt$v=98$r=12"));
  }

  // =========================================================================
  // HTTP/3 Listener Missing/Invalid cert_path and key_path Tests
  // =========================================================================

  #[test]
  fn test_validate_http3_listener_missing_cert_path() {
    ensure_crypto_provider();

    let (_, key_path) = generate_test_certificates();

    // Config without cert_path
    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "key_path": "{}"
}}"#,
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&key_path);

    // No cert_path validation error since cert_path is not present
    // The listener builder will handle this
    let cert_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("cert_path"))
      .collect();
    assert!(cert_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_missing_key_path() {
    ensure_crypto_provider();

    let (cert_path, _) = generate_test_certificates();

    // Config without key_path
    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}"
}}"#,
      cert_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);

    // No key_path validation error since key_path is not present
    // The listener builder will handle this
    let key_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("key_path"))
      .collect();
    assert!(key_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_cert_path_not_string() {
    ensure_crypto_provider();

    let (_, key_path) = generate_test_certificates();

    // Config with cert_path as a number
    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": 123,
  "key_path": "{}"
}}"#,
      key_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&key_path);

    // No cert_path validation error since cert_path is not a string
    // The listener builder will handle this
    let cert_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("cert_path"))
      .collect();
    assert!(cert_errors.is_empty());
  }

  #[test]
  fn test_validate_http3_listener_key_path_not_string() {
    ensure_crypto_provider();

    let (cert_path, _) = generate_test_certificates();

    // Config with key_path as a number
    let args = serde_yaml::from_str(&format!(
      r#"{{
  "address": "127.0.0.1:8443",
  "cert_path": "{}",
  "key_path": 456
}}"#,
      cert_path.to_str().unwrap()
    ))
    .unwrap();

    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "http3.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);

    let _ = std::fs::remove_file(&cert_path);

    // No key_path validation error since key_path is not a string
    // The listener builder will handle this
    let key_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.location.contains("key_path"))
      .collect();
    assert!(key_errors.is_empty());
  }
}
