//! Configuration validation orchestration.

use super::listener::ListenerPropertiesProvider;
use super::listener_validation::{
  validate_address_conflicts, validate_hostname,
  validate_hostname_conflicts, validate_hostname_routing_compatibility,
  validate_listener_addresses, validate_listener_references,
};
use super::service::validate_service;
use super::tls::validate_server_tls;
use super::{Config, ConfigError, ConfigErrorCollector};

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
pub fn validate_config(
  config: &Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &dyn ListenerPropertiesProvider,
) {
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
    listener_manager,
  );

  // Validate address conflicts across all servers
  validate_address_conflicts(config, collector, listener_manager);

  // Validate hostname conflicts across servers
  validate_hostname_conflicts(config, collector, listener_manager);
}
