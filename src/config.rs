//! Configuration types, parsing, and validation.
//!
//! This module provides:
//! - Core configuration types (Config, Server, Service, ListenerConfig)
//! - Configuration parsing from YAML files
//! - Configuration validation with detailed error reporting
//! - `SerializedArgs` type for configuration data

mod auth;
mod cli;
mod error;
mod global;
mod listener;
mod listener_validation;
mod service;
mod tls;
mod validate;

#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod listener_validation_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod tls_tests;
#[cfg(test)]
mod validate_tests;

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

// Re-export types from submodules
pub use self::auth::UserCredential;
pub use self::cli::CmdOpt;
pub use self::error::{ConfigError, ConfigErrorCollector};
pub use self::listener::{
  ListenerConfig, ListenerPropertiesProvider, ListenerPropertyValues,
  TransportLayer,
};
pub use self::service::{Service, ServiceRaw};
pub use self::tls::{CertificateConfig, ServerTlsConfig};
pub use self::validate::validate_config;

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
  #[serde(default)]
  pub plugins: HashMap<String, SerializedArgs>,
  #[serde(default)]
  pub tls_provider: Option<String>,
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
  pub plugins: HashMap<String, SerializedArgs>,
  pub tls_provider: Option<String>,
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
  /// Parse config from a string
  pub fn parse_string(&mut self, s: &str) -> Result<()> {
    let raw: ConfigRaw = serde_yaml::from_str(s)?;

    self.server_threads = raw.server_threads;
    self.listeners = raw.listeners;
    self.servers = raw.servers;
    self.plugins = raw.plugins;
    self.tls_provider = raw.tls_provider;

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
}
