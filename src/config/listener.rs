//! Listener configuration types and validation.

use std::collections::HashMap;
use std::net::SocketAddr;

use serde::Deserialize;

use super::{
  ConfigErrorCollector, ConfigErrorKind, SerializedArgs,
  ServerTlsConfig,
};

/// Listener configuration.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Listener {
  /// Listener type (http, https, http3, socks5)
  pub kind: String,
  /// Network addresses to listen on (framework field)
  pub addresses: Vec<String>,
  /// Listener-specific configuration arguments
  pub args: SerializedArgs,
}

/// Validate a single listener configuration.
///
/// Validates:
/// - TLS requirement for https and http3 listeners
/// - Address parsing
/// - HTTP/3 specific configuration
pub fn validate_listener(
  listener: &Listener,
  location: &str,
  server_tls: Option<&ServerTlsConfig>,
  collector: &mut ConfigErrorCollector,
) {
  // Check TLS requirement for https and http3 listeners
  match listener.kind.as_str() {
    "https" | "http3" => {
      if server_tls.is_none() {
        collector.add(
          location.to_string(),
          format!(
            "listener kind '{}' requires server-level 'tls' configuration",
            listener.kind
          ),
          ConfigErrorKind::InvalidFormat,
        );
        return;
      }
    }
    _ => {}
  }

  // Validate addresses
  validate_listener_addresses(&listener.addresses, location, collector);

  // Validate HTTP/3 listener specific configuration
  if listener.kind == "http3" {
    validate_http3_listener_args(&listener.args, location, collector);
  }
}

/// Validate listener addresses.
pub fn validate_listener_addresses(
  addresses: &[String],
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if addresses.is_empty() {
    collector.add(
      format!("{}.addresses", location),
      "addresses list cannot be empty".to_string(),
      ConfigErrorKind::InvalidAddress,
    );
    return;
  }
  for (addr_idx, addr_str) in addresses.iter().enumerate() {
    if addr_str.parse::<std::net::SocketAddr>().is_err() {
      collector.add(
        format!("{}.addresses[{}]", location, addr_idx),
        format!("invalid address '{}'", addr_str),
        ConfigErrorKind::InvalidAddress,
      );
    }
  }
}

/// Validate a single hostname pattern.
///
/// Valid patterns:
/// - Exact hostname: "api.example.com"
/// - Wildcard pattern: "*.example.com" (must have at least one dot after *)
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
    collector.add(
      location.to_string(),
      "hostname cannot be empty".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
    return;
  }

  // Check for wildcard patterns
  if let Some(after_star) = hostname.strip_prefix('*') {
    if !after_star.starts_with('.') || after_star.is_empty() {
      collector.add(
        location.to_string(),
        format!("invalid wildcard hostname '{}'", hostname),
        ConfigErrorKind::InvalidFormat,
      );
    } else {
      let suffix = &after_star[1..];
      if suffix.is_empty() || !suffix.contains('.') {
        collector.add(
          location.to_string(),
          format!("invalid wildcard hostname '{}'", hostname),
          ConfigErrorKind::InvalidFormat,
        );
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
) {
  use crate::listeners::ListenerBuilderSet;

  let registry = ListenerBuilderSet::global();

  for (server_idx, server) in config.servers.iter().enumerate() {
    if server.hostnames.is_empty() {
      continue;
    }

    for (listener_idx, listener) in server.listeners.iter().enumerate() {
      if let Some(props) = registry.props(&listener.kind) {
        if !props.supports_hostname_routing {
          collector.add(
            format!("servers[{}].listeners[{}]", server_idx, listener_idx),
            format!(
              "listener kind '{}' does not support hostname routing, \
               but server '{}' has hostnames configured",
              listener.kind, server.name
            ),
            ConfigErrorKind::InvalidFormat,
          );
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
/// - Multiple default servers (empty hostnames) on same address+kind: CONFLICT
pub fn validate_address_conflicts(
  config: &super::Config,
  collector: &mut ConfigErrorCollector,
) {
  use crate::listener::TransportLayer;
  use crate::listeners::ListenerBuilderSet;

  let registry = ListenerBuilderSet::global();
  let mut address_map: HashMap<SocketAddr, Vec<AddressUsage>> =
    HashMap::new();

  for server in &config.servers {
    for listener in &server.listeners {
      let _props = match registry.props(&listener.kind) {
        Some(p) => p,
        None => continue,
      };

      for addr_str in &listener.addresses {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
          let usage = AddressUsage {
            server_name: server.name.clone(),
            listener_kind: listener.kind.clone(),
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

    // Group by transport layer
    let tcp_usages: Vec<_> = usages
      .iter()
      .filter(|u| {
        registry
          .props(&u.listener_kind)
          .map(|p| p.transport_layer == TransportLayer::Tcp)
          .unwrap_or(false)
      })
      .collect();
    let udp_usages: Vec<_> = usages
      .iter()
      .filter(|u| {
        registry
          .props(&u.listener_kind)
          .map(|p| p.transport_layer == TransportLayer::Udp)
          .unwrap_or(false)
      })
      .collect();

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
        collector.add(
          format!("address conflict on {}", addr),
          format!(
            "TCP address conflict: different listener kinds ({}) on same address",
            details.join(", ")
          ),
          ConfigErrorKind::AddressConflict,
        );
      } else {
        check_hostname_routing_conflicts(&tcp_usages, addr, registry, collector);
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
        collector.add(
          format!("address conflict on {}", addr),
          format!(
            "UDP address conflict: different listener kinds ({}) on same address",
            details.join(", ")
          ),
          ConfigErrorKind::AddressConflict,
        );
      } else {
        check_hostname_routing_conflicts(&udp_usages, addr, registry, collector);
      }
    }
  }
}

/// Check for hostname routing conflicts sharing the same address+kind.
pub fn check_hostname_routing_conflicts(
  usages: &[&AddressUsage],
  addr: SocketAddr,
  registry: &crate::listeners::ListenerBuilderSet,
  collector: &mut ConfigErrorCollector,
) {
  let kind = usages[0].listener_kind.as_str();
  let supports_hostname_routing = registry
    .props(kind)
    .map(|p| p.supports_hostname_routing)
    .unwrap_or(false);

  if !supports_hostname_routing {
    // Doesn't support hostname routing - multiple instances is a conflict
    if usages.len() > 1 {
      let servers: Vec<_> =
        usages.iter().map(|u| u.server_name.as_str()).collect();
      collector.add(
        format!("address conflict on {}", addr),
        format!(
          "multiple {} listeners on same address without hostname routing support (servers: {})",
          kind,
          servers.join(", ")
        ),
        ConfigErrorKind::AddressConflict,
      );
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
    collector.add(
      format!("address conflict on {}", addr),
      format!(
        "multiple default servers ({}) on same address (only one server per address can have empty hostnames)",
        default_servers.join(", ")
      ),
      ConfigErrorKind::AddressConflict,
    );
  }

  for (hostname, servers) in hostname_map {
    if servers.len() > 1 {
      collector.add(
        format!("hostname conflict on {}", addr),
        format!(
          "'{}' defined in multiple servers ({})",
          hostname,
          servers.join(", ")
        ),
        ConfigErrorKind::AddressConflict,
      );
    }
  }
}

/// Validate HTTP/3 listener specific configuration.
///
/// Note: Address validation is handled by validate_listener_addresses.
/// Note: TLS and auth are now at server level, not listener level.
pub fn validate_http3_listener_args(
  args: &SerializedArgs,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if let Some(quic) = args.get("quic") {
    validate_quic_config(
      quic,
      &format!("{}.args.quic", location),
      collector,
    );
  }
}

/// Validate QUIC configuration parameters.
pub fn validate_quic_config(
  quic: &SerializedArgs,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if let Some(v) = quic.get("max_concurrent_bidi_streams")
    && let Some(n) = v.as_u64()
    && (!(1..=10000).contains(&n))
  {
    collector.add(
      format!("{}.max_concurrent_bidi_streams", location),
      format!("invalid value {}, expected range 1-10000", n),
      ConfigErrorKind::InvalidFormat,
    );
  }

  if let Some(v) = quic.get("max_idle_timeout_ms")
    && let Some(n) = v.as_u64()
    && n == 0
  {
    collector.add(
      format!("{}.max_idle_timeout_ms", location),
      "invalid value 0, expected value > 0".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
  }

  if let Some(v) = quic.get("initial_mtu")
    && let Some(n) = v.as_u64()
    && (!(1200..=9000).contains(&n))
  {
    collector.add(
      format!("{}.initial_mtu", location),
      format!("invalid value {}, expected range 1200-9000", n),
      ConfigErrorKind::InvalidFormat,
    );
  }

  if let Some(v) = quic.get("send_window")
    && let Some(n) = v.as_u64()
    && n == 0
  {
    collector.add(
      format!("{}.send_window", location),
      "invalid value 0, expected value > 0".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
  }

  if let Some(v) = quic.get("receive_window")
    && let Some(n) = v.as_u64()
    && n == 0
  {
    collector.add(
      format!("{}.receive_window", location),
      "invalid value 0, expected value > 0".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_listener_default() {
    let listener = Listener::default();
    assert!(listener.kind.is_empty());
    assert!(listener.addresses.is_empty());
  }

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
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
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
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("addresses list cannot be empty"));
    assert!(found);
  }

  // =========================================================================
  // validate_hostname Tests
  // =========================================================================

  #[test]
  fn test_validate_hostname_empty_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("", "test.hostname", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location == "test.hostname"
        && e.message.contains("hostname cannot be empty")
    });
    assert!(found);
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
    assert!(
      collector
        .errors()
        .iter()
        .any(|e| e.message.contains("invalid wildcard hostname"))
    );
  }

  #[test]
  fn test_validate_hostname_wildcard_no_dot_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("*example.com", "test.hostname", &mut collector);
    assert!(collector.has_errors());
    assert!(
      collector
        .errors()
        .iter()
        .any(|e| e.message.contains("invalid wildcard hostname"))
    );
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
  // validate_listener Tests (TLS requirement)
  // =========================================================================

  #[test]
  fn test_validate_https_without_tls_is_error() {
    let listener = Listener {
      kind: "https".to_string(),
      addresses: vec!["127.0.0.1:8443".to_string()],
      args: serde_yaml::Value::Null,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener(&listener, "test", None, &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_http3_without_tls_is_error() {
    let listener = Listener {
      kind: "http3".to_string(),
      addresses: vec!["127.0.0.1:8443".to_string()],
      args: serde_yaml::Value::Null,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener(&listener, "test", None, &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_http_without_tls_is_valid() {
    let listener = Listener {
      kind: "http".to_string(),
      addresses: vec!["127.0.0.1:8080".to_string()],
      args: serde_yaml::Value::Null,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener(&listener, "test", None, &mut collector);
    let found = collector.errors().iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(!found, "HTTP should not require TLS");
  }

  // =========================================================================
  // validate_quic_config Tests
  // =========================================================================

  #[test]
  fn test_validate_quic_config_valid() {
    let quic = serde_yaml::from_str(
      r#"{max_concurrent_bidi_streams: 100, max_idle_timeout_ms: 30000, initial_mtu: 1200, send_window: 1048576, receive_window: 1048576}"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_empty() {
    let quic: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_quic_config_bidi_streams_too_low() {
    let quic =
      serde_yaml::from_str(r#"{max_concurrent_bidi_streams: 0}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location.contains("max_concurrent_bidi_streams")
        && e.message.contains("expected range 1-10000")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_quic_config_bidi_streams_too_high() {
    let quic =
      serde_yaml::from_str(r#"{max_concurrent_bidi_streams: 10001}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location.contains("max_concurrent_bidi_streams")
        && e.message.contains("expected range 1-10000")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_quic_config_bidi_streams_boundary_low() {
    let quic =
      serde_yaml::from_str(r#"{max_concurrent_bidi_streams: 1}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_bidi_streams_boundary_high() {
    let quic =
      serde_yaml::from_str(r#"{max_concurrent_bidi_streams: 10000}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_idle_timeout_zero() {
    let quic =
      serde_yaml::from_str(r#"{max_idle_timeout_ms: 0}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location.contains("max_idle_timeout_ms")
        && e.message.contains("expected value > 0")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_quic_config_idle_timeout_valid() {
    let quic =
      serde_yaml::from_str(r#"{max_idle_timeout_ms: 1}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_initial_mtu_too_low() {
    let quic = serde_yaml::from_str(r#"{initial_mtu: 1199}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location.contains("initial_mtu")
        && e.message.contains("expected range 1200-9000")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_quic_config_initial_mtu_too_high() {
    let quic = serde_yaml::from_str(r#"{initial_mtu: 9001}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location.contains("initial_mtu")
        && e.message.contains("expected range 1200-9000")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_quic_config_initial_mtu_boundary_low() {
    let quic = serde_yaml::from_str(r#"{initial_mtu: 1200}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_initial_mtu_boundary_high() {
    let quic = serde_yaml::from_str(r#"{initial_mtu: 9000}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_send_window_zero() {
    let quic = serde_yaml::from_str(r#"{send_window: 0}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location.contains("send_window")
        && e.message.contains("expected value > 0")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_quic_config_send_window_valid() {
    let quic = serde_yaml::from_str(r#"{send_window: 1}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_receive_window_zero() {
    let quic = serde_yaml::from_str(r#"{receive_window: 0}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.location.contains("receive_window")
        && e.message.contains("expected value > 0")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_quic_config_receive_window_valid() {
    let quic = serde_yaml::from_str(r#"{receive_window: 1}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_quic_config_multiple_errors() {
    let quic = serde_yaml::from_str(
      r#"{max_concurrent_bidi_streams: 0, max_idle_timeout_ms: 0, initial_mtu: 500, send_window: 0, receive_window: 0}"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    assert_eq!(collector.errors().len(), 5);
  }

  // =========================================================================
  // validate_http3_listener_args Tests
  // =========================================================================

  #[test]
  fn test_validate_http3_listener_args_no_quic() {
    let args = serde_yaml::from_str(r#"{}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_http3_listener_args(&args, "test", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_http3_listener_args_valid_quic() {
    let args = serde_yaml::from_str(
      r#"{quic: {max_concurrent_bidi_streams: 100, initial_mtu: 1200}}"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_http3_listener_args(&args, "test", &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_validate_http3_listener_args_invalid_quic() {
    let args = serde_yaml::from_str(
      r#"{quic: {max_concurrent_bidi_streams: 0}}"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_http3_listener_args(&args, "test", &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.location.contains("quic.max_concurrent_bidi_streams"));
    assert!(found);
  }

  // =========================================================================
  // validate_hostname_routing_compatibility Tests
  // =========================================================================

  #[test]
  fn test_validate_hostname_routing_socks5_with_hostnames_error() {
    // Negative: socks5 does NOT support hostname routing
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "socks_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![Listener {
          kind: "socks5".to_string(),
          addresses: vec!["127.0.0.1:1080".to_string()],
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.message.contains("does not support hostname routing")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_hostname_routing_socks5_empty_hostnames_ok() {
    // Positive: socks5 with empty hostnames is valid
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "socks_server".to_string(),
        hostnames: vec![],
        listeners: vec![Listener {
          kind: "socks5".to_string(),
          addresses: vec!["127.0.0.1:1080".to_string()],
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_http_with_hostnames_ok() {
    // Positive: http supports hostname routing
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "http_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![Listener {
          kind: "http".to_string(),
          addresses: vec!["127.0.0.1:8080".to_string()],
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_https_with_hostnames_ok() {
    // Positive: https supports hostname routing
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "https_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![Listener {
          kind: "https".to_string(),
          addresses: vec!["127.0.0.1:8443".to_string()],
          args: serde_yaml::Value::Null,
        }],
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
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_http3_with_hostnames_ok() {
    // Positive: http3 supports hostname routing
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "http3_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![Listener {
          kind: "http3".to_string(),
          addresses: vec!["127.0.0.1:443".to_string()],
          args: serde_yaml::Value::Null,
        }],
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
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_mixed_listeners_error() {
    // Negative: one server with http + socks5, hostnames configured
    // socks5 doesn't support hostname routing, should error
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "mixed_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![
          Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          },
          Listener {
            kind: "socks5".to_string(),
            addresses: vec!["127.0.0.1:1080".to_string()],
            args: serde_yaml::Value::Null,
          },
        ],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(collector.has_errors());
    // Should have exactly one error for the socks5 listener
    let errors: Vec<_> = collector.errors().iter()
      .filter(|e| e.message.contains("does not support hostname routing"))
      .collect();
    assert_eq!(errors.len(), 1);
    // Error should point to the socks5 listener
    assert!(errors[0].location.contains("listeners[1]"));
  }

  #[test]
  fn test_validate_hostname_routing_multiple_servers_partial_error() {
    // Multiple servers: one valid, one invalid
    let config = super::super::Config {
      servers: vec![
        super::super::Server {
          name: "http_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        super::super::Server {
          name: "socks_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "socks5".to_string(),
            addresses: vec!["127.0.0.1:1080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(collector.has_errors());
    // Only socks_server should have error (servers[1])
    let errors: Vec<_> = collector.errors().iter()
      .filter(|e| e.message.contains("does not support hostname routing"))
      .collect();
    assert_eq!(errors.len(), 1);
    // Error location should reference the second server
    assert!(errors[0].location.contains("servers[1]"));
  }

  #[test]
  fn test_validate_hostname_routing_unknown_listener_kind_skipped() {
    // Unknown listener kind should be skipped (no error)
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "unknown_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![Listener {
          kind: "unknown_kind".to_string(),
          addresses: vec!["127.0.0.1:9999".to_string()],
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_hostname_routing_compatibility(&config, &mut collector);
    // Unknown listener kind is skipped, no error
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_no_hostnames_skipped() {
    // Server without hostnames should be skipped entirely
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "default_server".to_string(),
        hostnames: vec![], // empty hostnames
        listeners: vec![Listener {
          kind: "socks5".to_string(),
          addresses: vec!["127.0.0.1:1080".to_string()],
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_hostname_routing_all_supported_listeners_ok() {
    // Server with http + https + http3, all support hostname routing
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "all_supported".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![
          Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          },
          Listener {
            kind: "https".to_string(),
            addresses: vec!["127.0.0.1:8443".to_string()],
            args: serde_yaml::Value::Null,
          },
          Listener {
            kind: "http3".to_string(),
            addresses: vec!["127.0.0.1:443".to_string()],
            args: serde_yaml::Value::Null,
          },
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
    validate_hostname_routing_compatibility(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  // =========================================================================
  // validate_address_conflicts Tests
  // =========================================================================

  fn has_error_containing(
    collector: &ConfigErrorCollector,
    substring: &str,
  ) -> bool {
    collector.errors().iter().any(|e| e.message.contains(substring))
  }

  #[test]
  fn test_address_conflict_tcp_vs_tcp_different_kind() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "socks5".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(&collector, "address conflict"));
  }

  #[test]
  fn test_address_same_kind_can_share_with_hostnames() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "default_server".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "api_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    assert!(!collector.has_errors(), "{:?}", collector.errors());
  }

  #[test]
  fn test_address_multiple_default_servers_conflict() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(
      &collector,
      "multiple default servers"
    ));
  }

  #[test]
  fn test_hostname_exact_duplicate_conflict() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(
      &collector,
      "'api.example.com' defined in multiple servers"
    ));
  }

  #[test]
  fn test_hostname_wildcard_duplicate_conflict() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(
      &collector,
      "'*.example.com' defined in multiple servers"
    ));
  }

  #[test]
  fn test_hostname_case_insensitive_conflict() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["API.EXAMPLE.COM".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(
      &collector,
      "'api.example.com' defined in multiple servers"
    ));
  }

  #[test]
  fn test_different_hostnames_no_conflict() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["web.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("defined in multiple servers"));
    assert!(!found);
  }

  #[test]
  fn test_wildcard_and_exact_no_conflict() {
    use crate::config::{Server, Service};

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "wildcard".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "specific".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            args: serde_yaml::Value::Null,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let mut collector = ConfigErrorCollector::new();
    validate_address_conflicts(&config, &mut collector);
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("defined in multiple servers"));
    assert!(!found);
  }
}
