//! Listener configuration types and validation.

use std::collections::HashMap;
use std::net::SocketAddr;

use serde::Deserialize;

use super::{ConfigError, ConfigErrorCollector, SerializedArgs};

/// Top-level listener configuration.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
  pub name: String,
  pub kind: String,
  pub addresses: Vec<String>,
  pub args: SerializedArgs,
}

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
  config: &super::Config,
) -> std::collections::HashMap<&str, &super::ListenerConfig> {
  config.listeners.iter().map(|l| (l.name.as_str(), l)).collect()
}

/// Validate that each server's listener references exist in
/// config.listeners.
pub fn validate_listener_references(
  config: &super::Config,
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
  config: &super::Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &crate::listeners::ListenerManager,
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

      if let Some(props) = registry.props(listener_kind) {
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

/// Address usage info for conflict detection.
pub struct AddressUsage {
  pub server_name: String,
  pub listener_kind: String,
  /// Hostnames for this server (empty = default server)
  pub hostnames: Vec<String>,
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
  config: &super::Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &crate::listeners::ListenerManager,
) {
  use crate::listener::TransportLayer;

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

      if registry.props(&lc.kind).is_none() {
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
      match registry.props(&u.listener_kind).map(|p| p.transport_layer)
      {
        Some(TransportLayer::Tcp) => tcp_usages.push(u),
        Some(TransportLayer::Udp) => udp_usages.push(u),
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

/// Check for hostname routing conflicts sharing the same address+kind.
pub fn check_hostname_routing_conflicts(
  usages: &[&AddressUsage],
  addr: SocketAddr,
  registry: &crate::listeners::ListenerManager,
  collector: &mut ConfigErrorCollector,
) {
  let kind = usages[0].listener_kind.as_str();
  let supports_hostname_routing = registry
    .props(kind)
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

  let mut default_servers: Vec<&str> = Vec::new();
  let mut hostname_map: HashMap<String, Vec<&str>> = HashMap::new();

  for usage in usages {
    if usage.hostnames.is_empty() {
      default_servers.push(&usage.server_name);
    } else {
      for hostname in &usage.hostnames {
        let normalized = hostname.to_lowercase();
        hostname_map
          .entry(normalized)
          .or_default()
          .push(&usage.server_name);
      }
    }
  }

  if default_servers.len() > 1 {
    collector.add(ConfigError::AddressConflict {
      location: format!("address conflict on {}", addr),
      message: format!(
        "multiple default servers ({}) on same address (only one \
         server per address can have empty hostnames)",
        default_servers.join(", ")
      ),
    });
  }

  for (hostname, servers) in hostname_map {
    if servers.len() > 1 {
      collector.add(ConfigError::AddressConflict {
        location: format!("hostname conflict on {}", addr),
        message: format!(
          "hostname '{}' defined in multiple servers ({})",
          hostname,
          servers.join(", ")
        ),
      });
    }
  }
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
  config: &super::Config,
  collector: &mut ConfigErrorCollector,
  listener_manager: &crate::listeners::ListenerManager,
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
      .and_then(|l| registry.props(&l.kind))
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
    let mut default_servers: Vec<&str> = Vec::new();
    let mut hostname_map: std::collections::HashMap<String, Vec<&str>> =
      std::collections::HashMap::new();

    for server in &servers {
      if server.hostnames.is_empty() {
        default_servers.push(&server.name);
      } else {
        for hostname in &server.hostnames {
          let normalized = hostname.to_lowercase();
          hostname_map
            .entry(normalized)
            .or_default()
            .push(&server.name);
        }
      }
    }

    if default_servers.len() > 1 {
      collector.add(ConfigError::AddressConflict {
        location: format!("listener '{}'", listener_name),
        message: format!(
          "multiple default servers ({}) with empty hostnames",
          default_servers.join(", ")
        ),
      });
    }

    for (hostname, server_names) in hostname_map {
      if server_names.len() > 1 {
        collector.add(ConfigError::AddressConflict {
          location: format!("listener '{}'", listener_name),
          message: format!(
            "hostname '{}' defined in multiple servers ({})",
            hostname,
            server_names.join(", ")
          ),
        });
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // =========================================================================
  // validate_listener_addresses Tests
  // =========================================================================

  #[test]
  fn test_validate_valid_address() {
    let addresses = vec!["127.0.0.1:8080".to_string()];
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&addresses, "test", &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_address() {
    let addresses = vec!["invalid:address".to_string()];
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&addresses, "test", &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert!(matches!(&errors[0], ConfigError::InvalidAddress { .. }));
  }

  #[test]
  fn test_validate_multiple_invalid_addresses() {
    let addresses = vec![
      "invalid1".to_string(),
      "127.0.0.1:8080".to_string(),
      "invalid2".to_string(),
    ];
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&addresses, "test", &mut collector);
    assert!(collector.has_errors());
    assert_eq!(collector.errors().len(), 2);
  }

  #[test]
  fn test_validate_addresses_empty_array() {
    let addresses: Vec<String> = vec![];
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&addresses, "test", &mut collector);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::InvalidAddress { message, .. } if message == "addresses list cannot be empty"
    ));
  }

  // =========================================================================
  // validate_hostname Tests
  // =========================================================================

  #[test]
  fn test_validate_hostname_empty_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("", "test.hostname", &mut collector);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::InvalidFormat { message, .. } if message == "hostname cannot be empty"
    ));
  }

  #[test]
  fn test_validate_hostname_valid_exact() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname(
      "api.example.com",
      "test.hostname",
      &mut collector,
    );
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_hostname_valid_single_label() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("localhost", "test.hostname", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_hostname_valid_wildcard() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("*.example.com", "test.hostname", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_hostname_bare_wildcard_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("*", "test.hostname", &mut collector);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::InvalidFormat { .. }
    ));
  }

  #[test]
  fn test_validate_hostname_wildcard_no_dot_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("*example.com", "test.hostname", &mut collector);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::InvalidFormat { .. }
    ));
  }

  #[test]
  fn test_validate_hostname_wildcard_with_subdomain_is_valid() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname(
      "*.sub.example.com",
      "test.hostname",
      &mut collector,
    );
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  // =========================================================================
  // validate_hostname_routing_compatibility Tests
  // =========================================================================

  #[test]
  fn test_validate_hostname_routing_socks5_with_hostnames_error() {
    // Negative: socks5 does NOT support hostname routing
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:1080".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "socks_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["socks5_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::InvalidFormat { .. }
    ));
  }

  #[test]
  fn test_validate_hostname_routing_socks5_empty_hostnames_ok() {
    // Positive: socks5 with empty hostnames is valid
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:1080".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "socks_server".to_string(),
        hostnames: vec![],
        listeners: vec!["socks5_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_http_with_hostnames_ok() {
    // Positive: http supports hostname routing
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "http_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_https_with_hostnames_ok() {
    // Positive: https supports hostname routing
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "https_main".to_string(),
        kind: "https".to_string(),
        addresses: vec!["127.0.0.1:8443".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "https_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["https_main".to_string()],
        service: "".to_string(),
        tls: Some(super::super::ServerTlsConfig {
          certificates: vec![],
          client_ca_certs: None,
        }),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_http3_with_hostnames_ok() {
    // Positive: http3 supports hostname routing
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http3_main".to_string(),
        kind: "http3".to_string(),
        addresses: vec!["127.0.0.1:443".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "http3_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http3_main".to_string()],
        service: "".to_string(),
        tls: Some(super::super::ServerTlsConfig {
          certificates: vec![],
          client_ca_certs: None,
        }),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_mixed_listeners_error() {
    // Negative: one server with http + socks5, hostnames configured
    // socks5 doesn't support hostname routing, should error
    let config = super::super::Config {
      listeners: vec![
        super::super::ListenerConfig {
          name: "http_main".to_string(),
          kind: "http".to_string(),
          addresses: vec!["127.0.0.1:8080".to_string()],
          ..Default::default()
        },
        super::super::ListenerConfig {
          name: "socks5_main".to_string(),
          kind: "socks5".to_string(),
          addresses: vec!["127.0.0.1:1080".to_string()],
          ..Default::default()
        },
      ],
      servers: vec![super::super::Server {
        name: "mixed_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![
          "http_main".to_string(),
          "socks5_main".to_string(),
        ],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(collector.has_errors());
    // Should have exactly one error for the socks5 listener
    let errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| matches!(e, ConfigError::InvalidFormat { .. }))
      .collect();
    assert_eq!(errors.len(), 1);
    // Error should point to the socks5 listener
    assert!(errors[0].location().contains("listeners[1]"));
  }

  #[test]
  fn test_validate_hostname_routing_multiple_servers_partial_error() {
    // Multiple servers: one valid, one invalid
    let config = super::super::Config {
      listeners: vec![
        super::super::ListenerConfig {
          name: "http_main".to_string(),
          kind: "http".to_string(),
          addresses: vec!["127.0.0.1:8080".to_string()],
          ..Default::default()
        },
        super::super::ListenerConfig {
          name: "socks5_main".to_string(),
          kind: "socks5".to_string(),
          addresses: vec!["127.0.0.1:1080".to_string()],
          ..Default::default()
        },
      ],
      servers: vec![
        super::super::Server {
          name: "http_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "socks_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["socks5_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(collector.has_errors());
    // Only socks_server should have error (servers[1])
    let errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| matches!(e, ConfigError::InvalidFormat { .. }))
      .collect();
    assert_eq!(errors.len(), 1);
    // Error location should reference the second server
    assert!(errors[0].location().contains("servers[1]"));
  }

  #[test]
  fn test_validate_hostname_routing_unknown_listener_kind_skipped() {
    // Unknown listener kind should be skipped (no error)
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "unknown_main".to_string(),
        kind: "unknown_kind".to_string(),
        addresses: vec!["127.0.0.1:9999".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "unknown_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["unknown_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    // Unknown listener kind is skipped, no error
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_no_hostnames_skipped() {
    // Server without hostnames should be skipped entirely
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:1080".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "default_server".to_string(),
        hostnames: vec![], // empty hostnames
        listeners: vec!["socks5_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_all_supported_listeners_ok() {
    // Server with http + https + http3, all support hostname routing
    let config = super::super::Config {
      listeners: vec![
        super::super::ListenerConfig {
          name: "http_main".to_string(),
          kind: "http".to_string(),
          addresses: vec!["127.0.0.1:8080".to_string()],
          ..Default::default()
        },
        super::super::ListenerConfig {
          name: "https_main".to_string(),
          kind: "https".to_string(),
          addresses: vec!["127.0.0.1:8443".to_string()],
          ..Default::default()
        },
        super::super::ListenerConfig {
          name: "http3_main".to_string(),
          kind: "http3".to_string(),
          addresses: vec!["127.0.0.1:443".to_string()],
          ..Default::default()
        },
      ],
      servers: vec![super::super::Server {
        name: "all_supported".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![
          "http_main".to_string(),
          "https_main".to_string(),
          "http3_main".to_string(),
        ],
        service: "".to_string(),
        tls: Some(super::super::ServerTlsConfig {
          certificates: vec![],
          client_ca_certs: None,
        }),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_routing_compatibility(
      &config,
      &mut collector,
      &lm,
    );
    assert!(!collector.has_errors());
  }

  // =========================================================================
  // validate_address_conflicts Tests
  // =========================================================================

  fn has_error_of_type(
    collector: &ConfigErrorCollector,
    discriminant: impl Fn(&ConfigError) -> bool,
  ) -> bool {
    collector.errors().iter().any(|e| discriminant(e))
  }

  #[test]
  fn test_address_conflict_tcp_vs_tcp_different_kind() {
    let config = super::super::Config {
      listeners: vec![
        super::super::ListenerConfig {
          name: "http_main".to_string(),
          kind: "http".to_string(),
          addresses: vec!["127.0.0.1:8080".to_string()],
          ..Default::default()
        },
        super::super::ListenerConfig {
          name: "socks5_main".to_string(),
          kind: "socks5".to_string(),
          addresses: vec!["127.0.0.1:8080".to_string()],
          ..Default::default()
        },
      ],
      servers: vec![
        super::super::Server {
          name: "server1".to_string(),
          hostnames: vec![],
          listeners: vec!["http_main".to_string()],
          service: "echo".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server2".to_string(),
          hostnames: vec![],
          listeners: vec!["socks5_main".to_string()],
          service: "echo".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(has_error_of_type(&collector, |e| matches!(
      e,
      ConfigError::AddressConflict { .. }
    )));
  }

  #[test]
  fn test_address_same_kind_can_share_with_hostnames() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "default_server".to_string(),
          hostnames: vec![],
          listeners: vec!["http_main".to_string()],
          service: "echo".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "api_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "echo".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_address_multiple_default_servers_conflict() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server1".to_string(),
          hostnames: vec![],
          listeners: vec!["http_main".to_string()],
          service: "echo".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server2".to_string(),
          hostnames: vec![],
          listeners: vec!["http_main".to_string()],
          service: "echo".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(has_error_of_type(&collector, |e| matches!(
      e,
      ConfigError::AddressConflict { .. }
    )));
  }

  #[test]
  fn test_hostname_exact_duplicate_conflict() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(has_error_of_type(&collector, |e| matches!(
      e,
      ConfigError::AddressConflict { .. }
    )));
  }

  #[test]
  fn test_hostname_wildcard_duplicate_conflict() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server_a".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server_b".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(has_error_of_type(&collector, |e| matches!(
      e,
      ConfigError::AddressConflict { .. }
    )));
  }

  #[test]
  fn test_hostname_case_insensitive_conflict() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server_a".to_string(),
          hostnames: vec!["API.EXAMPLE.COM".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(has_error_of_type(&collector, |e| matches!(
      e,
      ConfigError::AddressConflict { .. }
    )));
  }

  #[test]
  fn test_different_hostnames_no_conflict() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server_b".to_string(),
          hostnames: vec!["web.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    let found = has_error_of_type(&collector, |e| {
      matches!(e, ConfigError::AddressConflict { .. })
    });
    assert!(!found);
  }

  #[test]
  fn test_wildcard_and_exact_no_conflict() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "wildcard".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "specific".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_address_conflicts(&config, &mut collector, &lm);
    let found = has_error_of_type(&collector, |e| {
      matches!(e, ConfigError::AddressConflict { .. })
    });
    assert!(!found);
  }

  // =========================================================================
  // validate_listener_references Tests
  // =========================================================================

  #[test]
  fn test_validate_listener_references_valid() {
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "s1".to_string(),
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_references(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "Valid reference should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_listener_references_not_found() {
    let config = super::super::Config {
      listeners: vec![],
      servers: vec![super::super::Server {
        name: "s1".to_string(),
        listeners: vec!["nonexistent".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_references(&config, &mut collector);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::NotFound { .. }
    ));
  }

  // =========================================================================
  // validate_hostname_conflicts Tests
  // =========================================================================

  #[test]
  fn test_validate_hostname_conflicts_socks5_multiple_servers() {
    // Two servers referencing the same socks5 listener
    // (non-hostname-routing)
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:1080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server_a".to_string(),
          hostnames: vec![],
          listeners: vec!["socks5_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server_b".to_string(),
          hostnames: vec![],
          listeners: vec!["socks5_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::InvalidFormat { .. }
    ));
  }

  #[test]
  fn test_validate_hostname_conflicts_socks5_single_server_ok() {
    // One server referencing socks5 listener is valid
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "socks5_main".to_string(),
        kind: "socks5".to_string(),
        addresses: vec!["127.0.0.1:1080".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "server_a".to_string(),
        hostnames: vec![],
        listeners: vec!["socks5_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_conflicts(&config, &mut collector, &lm);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_hostname_conflicts_http_hostname_overlap() {
    // Two servers with overlapping hostnames on the same http listener
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::AddressConflict { .. }
    ));
  }

  #[test]
  fn test_validate_hostname_conflicts_http_multiple_defaults() {
    // Two default servers (empty hostnames) on the same http listener
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "default_a".to_string(),
          hostnames: vec![],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "default_b".to_string(),
          hostnames: vec![],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_conflicts(&config, &mut collector, &lm);
    assert!(collector.has_errors());
    assert!(matches!(
      &collector.errors()[0],
      ConfigError::AddressConflict { .. }
    ));
  }

  #[test]
  fn test_validate_hostname_conflicts_http_no_overlap_ok() {
    // Two servers with different hostnames on the same http listener is
    // valid
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![
        super::super::Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "server_b".to_string(),
          hostnames: vec!["web.example.com".to_string()],
          listeners: vec!["http_main".to_string()],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_conflicts(&config, &mut collector, &lm);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_hostname_conflicts_single_server_skipped() {
    // Single server per listener is always valid (no conflict possible)
    let config = super::super::Config {
      listeners: vec![super::super::ListenerConfig {
        name: "http_main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        ..Default::default()
      }],
      servers: vec![super::super::Server {
        name: "server_a".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec!["http_main".to_string()],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    let lm = crate::listeners::ListenerManager::new();
    validate_hostname_conflicts(&config, &mut collector, &lm);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }
}
