//! module: config::listener_validation
//! responsibility: validate listener routing relationships
//! public operations: validate_listener_addresses,
//! validate_hostname, validate_listener_references,
//! validate_hostname_conflicts
//! data entities: none
//! tests: listener_validation_conflict_tests.rs,
//! listener_validation_test_support_tests.rs,
//! listener_validation_tests.rs

//! Listener configuration validation functions.

use std::collections::HashMap;

use super::{Config, ConfigError, ConfigErrorCollector};

/// Validate listener addresses.
pub(super) fn validate_listener_addresses(
  addresses: &[String],
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if addresses.is_empty() {
    collector.add(ConfigError::InvalidAddress {
      location: format!("{}.addresses", location),
      message: "addresses list cannot be empty".into(),
    });
    return;
  }
  for (addr_idx, addr_str) in addresses.iter().enumerate() {
    if addr_str.parse::<std::net::SocketAddr>().is_err() {
      collector.add(ConfigError::InvalidAddress {
        location: format!("{}.addresses[{}]", location, addr_idx),
        message: format!("invalid address '{}'", addr_str),
      });
    }
  }
}

/// Validate a single hostname pattern.
///
/// Valid patterns:
/// - Exact hostname: "api.example.com"
/// - Wildcard pattern: "*.example.com" (must have at least one dot
///   after *)
///
/// Invalid patterns:
/// - Empty string
/// - Wildcard without domain: "*"
/// - Wildcard without dot: "*example.com"
pub(super) fn validate_hostname(
  hostname: &str,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if hostname.is_empty() {
    collector.add(ConfigError::InvalidFormat {
      location: location.to_string(),
      message: "hostname cannot be empty".into(),
    });
    return;
  }

  // Check for wildcard patterns
  if let Some(after_star) = hostname.strip_prefix('*') {
    if !after_star.starts_with('.') || after_star.is_empty() {
      collector.add(ConfigError::InvalidFormat {
        location: location.to_string(),
        message: format!("invalid wildcard hostname '{}'", hostname),
      });
    } else {
      let suffix = &after_star[1..];
      if suffix.is_empty() || !suffix.contains('.') {
        collector.add(ConfigError::InvalidFormat {
          location: location.to_string(),
          message: format!("invalid wildcard hostname '{}'", hostname),
        });
      }
    }
  }
}

/// Validate that each server's listener references exist in
/// config.listeners.
pub(super) fn validate_listener_references(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  let listener_names: std::collections::HashSet<&str> =
    config.listeners().iter().map(|l| l.name()).collect();

  for (server_idx, server) in config.servers().iter().enumerate() {
    for (listener_idx, listener_name) in
      server.listeners().iter().enumerate()
    {
      if !listener_names.contains(listener_name.as_str()) {
        collector.add(ConfigError::NotFound {
          location: format!(
            "servers[{}].listeners[{}]",
            server_idx, listener_idx
          ),
          message: format!("listener '{}' not found", listener_name),
        });
      }
    }
  }
}

/// Collect hostname overlaps from a list of (server_name, hostnames)
/// pairs.
///
/// Returns (default_servers, hostname_map) where:
/// - default_servers: servers with empty hostnames
/// - hostname_map: lowercase hostname → list of server names
fn collect_hostname_overlaps<'a>(
  entries: impl Iterator<Item = (&'a str, &'a [String])>,
) -> (Vec<&'a str>, HashMap<String, Vec<&'a str>>) {
  let mut default_servers = Vec::new();
  let mut hostname_map: HashMap<String, Vec<&str>> = HashMap::new();

  for (server_name, hostnames) in entries {
    if hostnames.is_empty() {
      default_servers.push(server_name);
    } else {
      for hostname in hostnames {
        let normalized = crate::hostname::normalize(hostname);
        hostname_map.entry(normalized).or_default().push(server_name);
      }
    }
  }

  (default_servers, hostname_map)
}

/// Report hostname overlap conflicts to the collector.
fn report_hostname_overlaps(
  default_servers: &[&str],
  hostname_map: &HashMap<String, Vec<&str>>,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if default_servers.len() > 1 {
    collector.add(ConfigError::HostnameConflict {
      location: location.to_string(),
      message: format!(
        "multiple default servers ({}) with empty hostnames",
        default_servers.join(", ")
      ),
    });
  }

  for (hostname, servers) in hostname_map {
    if servers.len() > 1 {
      collector.add(ConfigError::HostnameConflict {
        location: location.to_string(),
        message: format!(
          "hostname '{}' defined in multiple servers ({})",
          hostname,
          servers.join(", ")
        ),
      });
    }
  }
}

/// Validate each listener's hostname index once, independently of its
/// listening addresses. Socket ownership belongs to bindings::validate.
pub(super) fn validate_hostname_conflicts(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  // Build listener_name -> Vec<&Server> mapping
  let mut listener_servers: std::collections::HashMap<
    &str,
    Vec<&super::Server>,
  > = std::collections::HashMap::new();
  for server in config.servers() {
    for listener_name in server.listeners() {
      listener_servers
        .entry(listener_name.as_str())
        .or_default()
        .push(server);
    }
  }

  for (listener_name, servers) in listener_servers {
    let entries =
      servers.iter().map(|s| (s.name.as_str(), s.hostnames.as_slice()));
    let (default_servers, hostname_map) =
      collect_hostname_overlaps(entries);
    let location = format!("listener '{}'", listener_name);
    report_hostname_overlaps(
      &default_servers,
      &hostname_map,
      &location,
      collector,
    );
  }
}
