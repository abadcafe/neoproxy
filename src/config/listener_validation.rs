//! Listener configuration validation functions.

use std::collections::HashMap;
use std::net::SocketAddr;

use super::listener::{
  AddressUsage, ListenerConfig, ListenerPropertiesProvider,
  TransportLayer,
};
use super::{Config, ConfigError, ConfigErrorCollector};

/// Validate listener addresses.
pub fn validate_listener_addresses(
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
pub fn validate_hostname(
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

/// Build a name -> ListenerConfig lookup map from the config.
fn build_listener_map(
  config: &Config,
) -> HashMap<&str, &ListenerConfig> {
  config.listeners.iter().map(|l| (l.name.as_str(), l)).collect()
}

/// Validate that each server's listener references exist in
/// config.listeners.
pub fn validate_listener_references(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  let listener_names: std::collections::HashSet<&str> =
    config.listeners.iter().map(|l| l.name.as_str()).collect();

  for (server_idx, server) in config.servers.iter().enumerate() {
    for (listener_idx, listener_name) in
      server.listeners.iter().enumerate()
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

/// Validate that listeners without hostname routing support
/// are not configured with hostnames.
///
/// If a listener doesn't support hostname routing (e.g., socks5),
/// the server's hostnames field must be empty.
pub fn validate_hostname_routing_compatibility(
  config: &Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &dyn ListenerPropertiesProvider,
) {
  let registry = listener_manager;

  // Build a name -> ListenerConfig lookup map
  let listener_map = build_listener_map(config);

  for (server_idx, server) in config.servers.iter().enumerate() {
    if server.hostnames.is_empty() {
      continue;
    }

    for (listener_idx, listener_name) in
      server.listeners.iter().enumerate()
    {
      // Look up ListenerConfig by name to get the kind
      let listener_kind = match listener_map.get(listener_name.as_str())
      {
        Some(lc) => lc.kind.as_str(),
        None => continue, /* Unknown listener name -
                           * validate_listener_references handles
                           * this */
      };

      if let Some(props) = registry.listener_props(listener_kind) {
        if !props.supports_hostname_routing {
          collector.add(ConfigError::InvalidFormat {
            location: format!(
              "servers[{}].listeners[{}]",
              server_idx, listener_idx
            ),
            message: format!(
              "listener kind '{}' does not support hostname routing, \
               but server '{}' has hostnames configured",
              listener_kind, server.name
            ),
          });
        }
      }
    }
  }
}

/// Validate address conflicts across all servers and listeners.
///
/// Rules:
/// - Different transport layer (TCP vs UDP): NO CONFLICT
/// - Same transport layer, different kind: CONFLICT
/// - Same kind, supports hostname routing: ALLOWED
/// - Same kind, NO hostname routing support (socks5): CONFLICT
/// - Multiple default servers (empty hostnames) on same address+kind:
///   CONFLICT
pub fn validate_address_conflicts(
  config: &Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &dyn ListenerPropertiesProvider,
) {
  use TransportLayer as TL;

  let registry = listener_manager;

  // Build a name -> ListenerConfig lookup map
  let listener_map = build_listener_map(config);

  let mut address_map: HashMap<SocketAddr, Vec<AddressUsage>> =
    HashMap::new();

  for server in &config.servers {
    for listener_name in &server.listeners {
      // Look up ListenerConfig by name
      let lc = match listener_map.get(listener_name.as_str()) {
        Some(lc) => lc,
        None => continue, /* Unknown listener name -
                           * validate_listener_references handles
                           * this */
      };

      if registry.listener_props(&lc.kind).is_none() {
        continue;
      }

      for addr_str in &lc.addresses {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
          let usage = AddressUsage {
            server_name: server.name.clone(),
            listener_kind: lc.kind.clone(),
            hostnames: server.hostnames.clone(),
          };
          address_map.entry(addr).or_default().push(usage);
        }
      }
    }
  }

  // Check for conflicts
  for (addr, usages) in address_map {
    if usages.len() <= 1 {
      continue;
    }

    use std::collections::HashSet;

    // Single-pass classification by transport layer
    let mut tcp_usages: Vec<&AddressUsage> = Vec::new();
    let mut udp_usages: Vec<&AddressUsage> = Vec::new();
    let mut other_usages: Vec<&AddressUsage> = Vec::new();

    for u in &usages {
      match registry
        .listener_props(&u.listener_kind)
        .map(|p| p.transport_layer)
      {
        Some(TL::Tcp) => tcp_usages.push(u),
        Some(TL::Udp) => udp_usages.push(u),
        _ => other_usages.push(u),
      }
    }

    // Check TCP conflicts
    if tcp_usages.len() > 1 {
      let kinds: HashSet<_> =
        tcp_usages.iter().map(|u| u.listener_kind.as_str()).collect();

      if kinds.len() > 1 {
        let details: Vec<_> = tcp_usages
          .iter()
          .map(|u| {
            format!("{} (server: {})", u.listener_kind, u.server_name)
          })
          .collect();
        collector.add(ConfigError::AddressConflict {
          location: format!("address conflict on {}", addr),
          message: format!(
            "TCP address conflict: different listener kinds ({}) on \
             same address",
            details.join(", ")
          ),
        });
      } else {
        check_hostname_routing_conflicts(
          &tcp_usages,
          addr,
          registry,
          collector,
        );
      }
    }

    // Check UDP conflicts
    if udp_usages.len() > 1 {
      let kinds: HashSet<_> =
        udp_usages.iter().map(|u| u.listener_kind.as_str()).collect();

      if kinds.len() > 1 {
        let details: Vec<_> = udp_usages
          .iter()
          .map(|u| {
            format!("{} (server: {})", u.listener_kind, u.server_name)
          })
          .collect();
        collector.add(ConfigError::AddressConflict {
          location: format!("address conflict on {}", addr),
          message: format!(
            "UDP address conflict: different listener kinds ({}) on \
             same address",
            details.join(", ")
          ),
        });
      } else {
        check_hostname_routing_conflicts(
          &udp_usages,
          addr,
          registry,
          collector,
        );
      }
    }

    // Check other transport layers (future extensibility)
    if other_usages.len() > 1 {
      let kinds: HashSet<_> =
        other_usages.iter().map(|u| u.listener_kind.as_str()).collect();

      if kinds.len() > 1 {
        let details: Vec<_> = other_usages
          .iter()
          .map(|u| {
            format!("{} (server: {})", u.listener_kind, u.server_name)
          })
          .collect();
        collector.add(ConfigError::AddressConflict {
          location: format!("address conflict on {}", addr),
          message: format!(
            "address conflict: different listener kinds ({}) on same \
             address",
            details.join(", ")
          ),
        });
      } else {
        check_hostname_routing_conflicts(
          &other_usages,
          addr,
          registry,
          collector,
        );
      }
    }
  }
}

/// Collect hostname overlaps from a list of (server_name, hostnames) pairs.
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
        let normalized = hostname.to_lowercase();
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

/// Check for hostname routing conflicts sharing the same address+kind.
fn check_hostname_routing_conflicts(
  usages: &[&AddressUsage],
  addr: SocketAddr,
  registry: &dyn ListenerPropertiesProvider,
  collector: &mut ConfigErrorCollector,
) {
  let kind = usages[0].listener_kind.as_str();
  let supports_hostname_routing = registry
    .listener_props(kind)
    .map(|p| p.supports_hostname_routing)
    .unwrap_or(false);

  if !supports_hostname_routing {
    // Doesn't support hostname routing - multiple instances is a
    // conflict
    if usages.len() > 1 {
      let servers: Vec<_> =
        usages.iter().map(|u| u.server_name.as_str()).collect();
      collector.add(ConfigError::AddressConflict {
        location: format!("address conflict on {}", addr),
        message: format!(
          "multiple {} listeners on same address without hostname \
           routing support (servers: {})",
          kind,
          servers.join(", ")
        ),
      });
    }
    return;
  }

  let entries = usages
    .iter()
    .map(|u| (u.server_name.as_str(), u.hostnames.as_slice()));
  let (default_servers, hostname_map) =
    collect_hostname_overlaps(entries);
  let location = format!("address conflict on {}", addr);
  report_hostname_overlaps(
    &default_servers,
    &hostname_map,
    &location,
    collector,
  );
}

/// Validate hostname conflicts by grouping servers by listener name.
///
/// This function checks two things:
/// 1. Non-hostname-routing listeners (e.g., socks5) can only have one
///    server
/// 2. Hostname-routing listeners cannot have overlapping hostnames
///    between servers
///
/// This is different from [`validate_address_conflicts`] which groups
/// by address+kind. This function groups by listener NAME, catching
/// cases where multiple servers reference the same listener on
/// different addresses.
///
/// **Intentional overlap:** When two servers reference the same
/// listener on the same address, both `validate_address_conflicts` and
/// `validate_hostname_conflicts` may detect the same hostname overlap.
/// This overlap is intentional -- the two functions serve different
/// primary purposes (address conflicts vs listener-level conflicts) and
/// provide complementary error messages.
pub fn validate_hostname_conflicts(
  config: &Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &dyn ListenerPropertiesProvider,
) {
  let registry = listener_manager;

  // Build name -> ListenerConfig lookup map
  let listener_map = build_listener_map(config);

  // Build listener_name -> Vec<&Server> mapping
  let mut listener_servers: std::collections::HashMap<
    &str,
    Vec<&super::Server>,
  > = std::collections::HashMap::new();
  for server in &config.servers {
    for listener_name in &server.listeners {
      listener_servers
        .entry(listener_name.as_str())
        .or_default()
        .push(server);
    }
  }

  for (listener_name, servers) in listener_servers {
    if servers.len() <= 1 {
      continue;
    }

    // Get listener kind and check supports_hostname_routing
    let supports_hostname_routing = listener_map
      .get(listener_name)
      .and_then(|l| registry.listener_props(&l.kind))
      .map(|p| p.supports_hostname_routing)
      .unwrap_or(false);

    if !supports_hostname_routing {
      // Non-hostname-routing listener: only one server can reference it
      let server_names: Vec<_> =
        servers.iter().map(|s| s.name.as_str()).collect();
      collector.add(ConfigError::InvalidFormat {
        location: format!("listener '{}'", listener_name),
        message: format!(
          "multiple servers ({}) reference a listener without \
           hostname routing support",
          server_names.join(", ")
        ),
      });
      continue;
    }

    // Hostname-routing listener: check hostname overlaps
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
