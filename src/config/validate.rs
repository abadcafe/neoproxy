//! module: config::validate
//! responsibility: orchestrate configuration validation
//! public operations: validate, validate_config
//! data entities: none
//! tests: validate_tests.rs

//! Configuration validation orchestration.

use super::document::Config;
use super::error::{ConfigError, ConfigErrorCollector};
use super::listener::ListenerPropertiesProvider;
use super::listener_validation::{
  validate_hostname, validate_hostname_conflicts,
  validate_listener_addresses, validate_listener_references,
};
use super::service::validate_service;
use super::tls::validate_server_tls;

impl Config {
  pub(crate) fn validate(
    &self,
    collector: &mut ConfigErrorCollector,
    listener_manager: &dyn ListenerPropertiesProvider,
  ) {
    validate_config(self, collector, listener_manager);
  }
}

/// Validate server_threads global setting.
fn validate_server_threads(
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
pub(super) fn validate_config(
  config: &Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &dyn ListenerPropertiesProvider,
) {
  super::bindings::validate(config, collector, listener_manager);

  // Validate global settings
  validate_server_threads(config.server_threads(), collector);

  // Collect all service names for reference validation
  let service_names: std::collections::HashSet<&str> =
    config.services().iter().map(|s| s.name()).collect();

  // Validate servers
  for (server_idx, server) in config.servers().iter().enumerate() {
    let server_location = format!("servers[{}]", server_idx);

    // Validate hostnames
    for (idx, hostname) in server.hostnames().iter().enumerate() {
      let hostname_location =
        format!("{}.hostnames[{}]", server_location, idx);
      validate_hostname(hostname, &hostname_location, collector);
    }

    // Certificate ownership is a per-server requirement, including
    // default servers and servers also bound to plaintext listeners. A
    // different server's identity on the same listener cannot satisfy
    // this contract.
    let required_by = config
      .listeners()
      .iter()
      .filter(|listener| {
        server.listeners().iter().any(|name| name == listener.name())
      })
      .filter(|listener| {
        listener_manager
          .listener_props(listener.kind())
          .is_some_and(|props| props.requires_server_certificate())
      })
      .map(|listener| {
        format!("'{}' ({})", listener.name(), listener.kind())
      })
      .collect::<Vec<_>>();
    if !required_by.is_empty()
      && server.tls().is_none_or(|tls| tls.certificates().is_empty())
    {
      collector.add(ConfigError::InvalidFormat {
        location: format!("{server_location}.certificates"),
        message: format!(
          "server '{}' must configure at least one certificate \
           because it uses listener(s): {}",
          server.name(),
          required_by.join(", ")
        ),
      });
    } else if let Some(tls) = server.tls() {
      validate_server_tls(tls, &server_location, collector);
    }

    // Validate service reference
    validate_service(
      &service_names,
      server_idx,
      server.service(),
      collector,
    );
  }

  // Validate listener addresses
  for (idx, listener) in config.listeners().iter().enumerate() {
    let location = format!("listeners[{}]", idx);
    validate_listener_addresses(
      listener.addresses(),
      &location,
      collector,
    );
  }

  // Validate listener references
  validate_listener_references(config, collector);

  // Validate hostname conflicts across servers
  validate_hostname_conflicts(config, collector);
}
