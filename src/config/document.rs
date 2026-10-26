//! module: document
//! responsibilities: parse and expose a NeoProxy configuration document
//! public operations: Config::{default, parse_str, load, accessors},
//! Debug data entities: ConfigRaw, Config
//! tests: config_tests.rs through config's public interface
use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::args::SerializedArgs;
use super::listener::ListenerConfig;
use super::server::Server;
use super::service::{self, Service};
use crate::redaction::Redacted;

/// Configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone)]
#[serde(default, deny_unknown_fields)]
struct ConfigRaw {
  #[serde(default)]
  listeners: Vec<ListenerConfig>,
  #[serde(default = "default_server_threads")]
  server_threads: usize,
  services: Vec<self::service::ServiceRaw>,
  servers: Vec<Server>,
  #[serde(default)]
  plugins: HashMap<String, SerializedArgs>,
  #[serde(default)]
  tls_provider: Option<String>,
}

impl std::fmt::Debug for ConfigRaw {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("ConfigRaw")
      .field("listeners", &self.listeners)
      .field("server_threads", &self.server_threads)
      .field("services", &self.services)
      .field("servers", &self.servers)
      .field("plugins", &Redacted(&self.plugins))
      .field("tls_provider", &self.tls_provider)
      .finish()
  }
}

fn default_server_threads() -> usize {
  4
}

/// Main configuration. Debug preserves configuration details while
/// masking password/token values in opaque plugin parameters.
#[derive(Clone)]
pub(crate) struct Config {
  pub(in crate::config) server_threads: usize,
  pub(in crate::config) listeners: Vec<ListenerConfig>,
  pub(in crate::config) services: Vec<Service>,
  pub(in crate::config) servers: Vec<Server>,
  pub(in crate::config) plugins: HashMap<String, SerializedArgs>,
  pub(in crate::config) tls_provider: Option<String>,
}

impl std::fmt::Debug for Config {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("Config")
      .field("server_threads", &self.server_threads)
      .field("listeners", &self.listeners)
      .field("services", &self.services)
      .field("servers", &self.servers)
      .field("plugins", &Redacted(&self.plugins))
      .field("tls_provider", &self.tls_provider)
      .finish()
  }
}

impl Default for Config {
  fn default() -> Self {
    Self {
      server_threads: 4,
      listeners: vec![],
      services: vec![],
      servers: vec![],
      plugins: HashMap::new(),
      tls_provider: None,
    }
  }
}

impl Config {
  /// Parse config from a string.
  ///
  /// Returns the parsed config without validating cross-module
  /// invariants such as listener compatibility.
  pub(crate) fn parse_str(s: &str) -> Result<Self> {
    let raw: ConfigRaw = serde_yaml::from_str(s)?;

    validate_unique_names(
      raw.listeners.iter().map(|item| item.name()),
      "listener",
    )?;
    validate_unique_names(
      raw.servers.iter().map(|item| item.name()),
      "server",
    )?;
    // Convert ServiceRaw -> Service using parse methods
    let services = raw
      .services
      .into_iter()
      .map(|sr| sr.parse())
      .collect::<Result<Vec<_>>>()?;

    validate_unique_names(
      services.iter().map(|item| item.name()),
      "service",
    )?;

    Ok(Self {
      server_threads: raw.server_threads,
      listeners: raw.listeners,
      services,
      servers: raw.servers,
      plugins: raw.plugins,
      tls_provider: raw.tls_provider,
    })
  }

  /// Read and parse config from a file
  fn parse_file(path: &str) -> Result<Self> {
    let s = std::fs::read_to_string(std::path::Path::new(path))
      .with_context(|| format!("read config file '{}'", path))?;
    Self::parse_str(&s)
  }

  /// Load configuration from a file.
  ///
  /// Returns the parsed config. Does not validate.
  pub(crate) fn load(path: &str) -> Result<Config> {
    Self::parse_file(path)
  }

  pub(crate) fn server_threads(&self) -> usize {
    self.server_threads
  }

  pub(crate) fn listeners(&self) -> &[ListenerConfig] {
    &self.listeners
  }

  pub(crate) fn services(&self) -> &[Service] {
    &self.services
  }

  pub(crate) fn servers(&self) -> &[Server] {
    &self.servers
  }

  pub(crate) fn plugins(&self) -> &HashMap<String, SerializedArgs> {
    &self.plugins
  }

  pub(crate) fn tls_provider(&self) -> Option<&str> {
    self.tls_provider.as_deref()
  }

  pub(crate) fn service_by_name(&self, name: &str) -> Option<&Service> {
    self.services.iter().find(|s| s.name() == name)
  }
}

fn validate_unique_names<'a>(
  names: impl Iterator<Item = &'a str>,
  kind: &str,
) -> Result<()> {
  let mut seen = std::collections::HashSet::new();
  for name in names {
    anyhow::ensure!(
      seen.insert(name),
      "duplicate {kind} name '{name}'"
    );
  }
  Ok(())
}

impl Config {
  /// Compile TLS before any worker starts or listener binds. The
  /// compiled snapshots are shared through the cloned configuration.
  pub(crate) fn compile_tls(&self) -> Result<()> {
    for server in self.servers() {
      if let Some(tls) = server.tls() {
        let _ = tls.compile(server.hostnames()).with_context(|| {
          format!("server '{}' TLS configuration", server.name())
        })?;
      }
    }
    Ok(())
  }
}
