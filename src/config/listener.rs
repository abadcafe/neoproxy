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
  #[serde(rename = "kind")]
  pub listener_name: String,
  pub args: SerializedArgs,
}

/// Transport layer type for address conflict detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportLayer {
  Tcp,
  Udp,
}

/// Listener kind category for conflict detection.
/// Includes whether the listener supports hostname-based routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListenerCategory {
  Http,   // http listener - TCP, supports hostname routing
  Https,  // https listener - TCP, supports hostname routing
  Http3,  // http3 listener - UDP, supports hostname routing
  Socks5, // socks5 listener - TCP, NO hostname routing
}

impl ListenerCategory {
  pub fn from_kind(kind: &str) -> Option<Self> {
    match kind {
      "http" => Some(Self::Http),
      "https" => Some(Self::Https),
      "http3" => Some(Self::Http3),
      "socks5" => Some(Self::Socks5),
      _ => None,
    }
  }

  pub fn transport_layer(&self) -> TransportLayer {
    match self {
      Self::Http | Self::Https | Self::Socks5 => TransportLayer::Tcp,
      Self::Http3 => TransportLayer::Udp,
    }
  }
}

/// Address usage info for conflict detection.
pub struct AddressUsage {
  pub server_name: String,
  pub listener_kind: String,
  pub listener_category: ListenerCategory,
  /// Hostnames for this server (empty = default server)
  pub hostnames: Vec<String>,
}

/// Extract addresses from listener args.
///
/// Tries 'addresses' (plural) first, then 'address' (singular) for
/// backward compatibility.
pub fn extract_addresses(args: &SerializedArgs) -> Vec<String> {
  let mut addresses = Vec::new();

  // Try 'addresses' (plural) field first
  if let Some(addrs) = args.get("addresses")
    && let Some(addr_list) = addrs.as_sequence()
  {
    for addr in addr_list {
      if let Some(addr_str) = addr.as_str() {
        addresses.push(addr_str.to_string());
      }
    }
  }

  // Try 'address' (singular) field for backward compatibility
  if addresses.is_empty()
    && let Some(addr) = args.get("address")
    && let Some(addr_str) = addr.as_str()
  {
    addresses.push(addr_str.to_string());
  }

  addresses
}

/// Validate a single listener configuration.
///
/// Validates:
/// - TLS requirement for https and http3 listeners
/// - Address parsing in listener args
/// - HTTP/3 specific configuration
pub fn validate_listener(
  listener: &Listener,
  location: &str,
  server_tls: Option<&ServerTlsConfig>,
  collector: &mut ConfigErrorCollector,
) {
  // Check TLS requirement for https and http3 listeners
  match listener.listener_name.as_str() {
    "https" | "http3" => {
      if server_tls.is_none() {
        collector.add(
          location.to_string(),
          format!(
            "listener kind '{}' requires server-level 'tls' configuration",
            listener.listener_name
          ),
          ConfigErrorKind::InvalidFormat,
        );
        return;
      }
    }
    _ => {}
  }

  // Validate addresses in listener args if present
  validate_listener_addresses(&listener.args, location, collector);

  // Validate HTTP/3 listener specific configuration
  if listener.listener_name == "http3" {
    validate_http3_listener_args(&listener.args, location, collector);
  }
}

/// Validate addresses in listener args.
pub fn validate_listener_addresses(
  args: &SerializedArgs,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  // Check if args has an "addresses" field
  match args.get("addresses") {
    Some(addresses) => {
      if let Some(addrs) = addresses.as_sequence() {
        if addrs.is_empty() {
          collector.add(
            format!("{}.args.addresses", location),
            "addresses list cannot be empty".to_string(),
            ConfigErrorKind::InvalidAddress,
          );
          return;
        }
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
    None => {
      // addresses field is missing - this is an error
      collector.add(
        format!("{}.args", location),
        "addresses field is required".to_string(),
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

/// Validate that SOCKS5 listeners are not configured with hostnames.
pub fn validate_socks5_hostnames(
  config: &super::Config,
  collector: &mut ConfigErrorCollector,
) {
  for (server_idx, server) in config.servers.iter().enumerate() {
    if !server.hostnames.is_empty() {
      let has_socks5 =
        server.listeners.iter().any(|l| l.listener_name == "socks5");
      if has_socks5 {
        collector.add(
          format!("servers[{}]", server_idx),
          "hostnames cannot be configured with SOCKS5 listener (SOCKS5 does not support hostname routing)".to_string(),
          ConfigErrorKind::InvalidFormat,
        );
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
/// - Multiple default servers (empty hostnames) on same address+kind: CONFLICT
pub fn validate_address_conflicts(
  config: &super::Config,
  collector: &mut ConfigErrorCollector,
) {
  let mut address_map: HashMap<SocketAddr, Vec<AddressUsage>> =
    HashMap::new();

  for server in &config.servers {
    for listener in &server.listeners {
      let category =
        match ListenerCategory::from_kind(&listener.listener_name) {
          Some(c) => c,
          None => continue,
        };

      let addresses = extract_addresses(&listener.args);

      for addr_str in addresses {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
          let usage = AddressUsage {
            server_name: server.name.clone(),
            listener_kind: listener.listener_name.clone(),
            listener_category: category,
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
        u.listener_category.transport_layer() == TransportLayer::Tcp
      })
      .collect();
    let udp_usages: Vec<_> = usages
      .iter()
      .filter(|u| {
        u.listener_category.transport_layer() == TransportLayer::Udp
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
        check_hostname_routing_conflicts(&tcp_usages, addr, collector);
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
        check_hostname_routing_conflicts(&udp_usages, addr, collector);
      }
    }
  }
}

/// Check for hostname routing conflicts sharing the same address+kind.
pub fn check_hostname_routing_conflicts(
  usages: &[&AddressUsage],
  addr: SocketAddr,
  collector: &mut ConfigErrorCollector,
) {
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
    assert!(listener.listener_name.is_empty());
  }

  #[test]
  fn test_listener_category_from_kind() {
    assert_eq!(
      ListenerCategory::from_kind("http"),
      Some(ListenerCategory::Http)
    );
    assert_eq!(
      ListenerCategory::from_kind("https"),
      Some(ListenerCategory::Https)
    );
    assert_eq!(
      ListenerCategory::from_kind("http3"),
      Some(ListenerCategory::Http3)
    );
    assert_eq!(
      ListenerCategory::from_kind("socks5"),
      Some(ListenerCategory::Socks5)
    );
    assert_eq!(ListenerCategory::from_kind("unknown"), None);
  }

  #[test]
  fn test_listener_category_transport_layer() {
    assert_eq!(
      ListenerCategory::Http.transport_layer(),
      TransportLayer::Tcp
    );
    assert_eq!(
      ListenerCategory::Https.transport_layer(),
      TransportLayer::Tcp
    );
    assert_eq!(
      ListenerCategory::Socks5.transport_layer(),
      TransportLayer::Tcp
    );
    assert_eq!(
      ListenerCategory::Http3.transport_layer(),
      TransportLayer::Udp
    );
  }

  // =========================================================================
  // validate_listener_addresses Tests
  // =========================================================================

  #[test]
  fn test_validate_valid_address() {
    let args =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&args, "test", &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_address() {
    let args =
      serde_yaml::from_str(r#"{addresses: ["invalid:address"]}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&args, "test", &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_multiple_invalid_addresses() {
    let args = serde_yaml::from_str(
      r#"{addresses: ["invalid1", "127.0.0.1:8080", "invalid2"]}"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&args, "test", &mut collector);
    assert!(collector.has_errors());
    assert_eq!(collector.errors().len(), 2);
  }

  #[test]
  fn test_validate_addresses_empty_array() {
    let args = serde_yaml::from_str(r#"{addresses: []}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&args, "test", &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("addresses list cannot be empty"));
    assert!(found);
  }

  #[test]
  fn test_validate_addresses_missing_field() {
    let args = serde_yaml::from_str(r#"{}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_addresses(&args, "test", &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("addresses field is required"));
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
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#)
        .unwrap();
    let listener =
      Listener { listener_name: "https".to_string(), args };
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
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#)
        .unwrap();
    let listener =
      Listener { listener_name: "http3".to_string(), args };
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
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let listener = Listener { listener_name: "http".to_string(), args };
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
  // validate_socks5_hostnames Tests
  // =========================================================================

  #[test]
  fn test_validate_socks5_with_hostnames_error() {
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "socks_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![Listener {
          listener_name: "socks5".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_socks5_hostnames(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.message.contains("hostnames cannot be configured with SOCKS5")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_socks5_without_hostnames_ok() {
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let config = super::super::Config {
      servers: vec![super::super::Server {
        name: "socks_server".to_string(),
        hostnames: vec![],
        listeners: vec![Listener {
          listener_name: "socks5".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_socks5_hostnames(&config, &mut collector);
    let found = collector.errors().iter().any(|e| {
      e.message.contains("hostnames cannot be configured with SOCKS5")
    });
    assert!(!found);
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

    let args1 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
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
            listener_name: "http".to_string(),
            args: args1,
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
            listener_name: "socks5".to_string(),
            args: args2,
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

    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
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
            listener_name: "http".to_string(),
            args: args.clone(),
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
            listener_name: "http".to_string(),
            args,
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

    let args1 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
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
            listener_name: "http".to_string(),
            args: args1,
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
            listener_name: "http".to_string(),
            args: args2,
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

    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args2,
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

    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args2,
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

    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["API.EXAMPLE.COM".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args2,
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

    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "server_a".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["web.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args2,
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

    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = super::super::Config {
      worker_threads: 1,
      log_directory: "logs/".to_string(),
      access_log: None,
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![
        Server {
          name: "wildcard".to_string(),
          hostnames: vec!["*.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "specific".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: args2,
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
