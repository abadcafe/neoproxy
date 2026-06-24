//! Configuration types, parsing, and validation.
//!
//! This module provides:
//! - Core configuration types (Config, Server, Service, ListenerConfig)
//! - Configuration parsing from YAML files
//! - Configuration validation with detailed error reporting
//! - `SerializedArgs` type for configuration data

mod auth;
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
mod global_tests;
#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod listener_validation_conflict_tests;
#[cfg(test)]
mod listener_validation_test_support;
#[cfg(test)]
mod listener_validation_test_support_tests;
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

pub(crate) use self::auth::UserCredential;
pub(crate) use self::error::{ConfigError, ConfigErrorCollector};
pub(crate) use self::listener::{
  ListenerConfig, ListenerPropertiesProvider, ListenerPropertyValues,
  TransportLayer,
};
pub(crate) use self::service::Service;
pub(crate) use self::tls::{CertificateConfig, ServerTlsConfig};

/// Serialized configuration arguments.
///
/// A type alias for `serde_yaml::Value`, used to pass configuration
/// data from YAML files to listener and service builders.
pub(crate) type SerializedArgs = serde_yaml::Value;

/// Layer configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
struct LayerRaw {
  kind: String,
  args: SerializedArgs,
}

/// Layer configuration (after kind parsing).
#[derive(Default, Clone, Debug)]
pub(crate) struct Layer {
  pub(in crate::config) plugin_name: String,
  pub(in crate::config) kind: String,
  pub(in crate::config) args: SerializedArgs,
}

impl Layer {
  pub(crate) fn plugin_name(&self) -> &str {
    &self.plugin_name
  }

  pub(crate) fn kind(&self) -> &str {
    &self.kind
  }

  pub(crate) fn args(&self) -> &SerializedArgs {
    &self.args
  }
}

/// Server configuration.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Server {
  pub(in crate::config) name: String,
  /// Virtual hostnames for this server (for SNI/Host routing)
  #[serde(default)]
  pub(in crate::config) hostnames: Vec<String>,
  /// TLS configuration (for https and http3 listeners)
  pub(in crate::config) tls: Option<ServerTlsConfig>,
  /// References to top-level listener names
  pub(in crate::config) listeners: Vec<String>,
  pub(in crate::config) service: String,
}

impl Server {
  pub(crate) fn name(&self) -> &str {
    &self.name
  }

  pub(crate) fn hostnames(&self) -> &[String] {
    &self.hostnames
  }

  pub(crate) fn tls(&self) -> Option<&ServerTlsConfig> {
    self.tls.as_ref()
  }

  pub(crate) fn listeners(&self) -> &[String] {
    &self.listeners
  }

  pub(crate) fn service(&self) -> &str {
    &self.service
  }
}

/// Configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
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

fn default_server_threads() -> usize {
  4
}

/// Main configuration.
#[derive(Clone, Debug)]
pub(crate) struct Config {
  pub(in crate::config) server_threads: usize,
  pub(in crate::config) listeners: Vec<ListenerConfig>,
  pub(in crate::config) services: Vec<Service>,
  pub(in crate::config) servers: Vec<Server>,
  pub(in crate::config) plugins: HashMap<String, SerializedArgs>,
  pub(in crate::config) tls_provider: Option<String>,
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

    // Convert ServiceRaw -> Service using parse methods
    let services = raw
      .services
      .into_iter()
      .map(|sr| sr.parse())
      .collect::<Result<Vec<_>>>()?;

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

  pub(crate) fn validate(
    &self,
    collector: &mut ConfigErrorCollector,
    listener_manager: &dyn ListenerPropertiesProvider,
  ) {
    self::validate::validate_config(self, collector, listener_manager);
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
