use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::process;

use crate::config::{
  AccessLogConfig, Config, Listener, ListenerAuthConfig,
  ServerTlsConfig, UserConfig,
};
use crate::plugin::SerializedArgs;

/// Configuration error kind
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigErrorKind {
  /// File read failed
  FileRead,
  /// YAML parsing failed
  YamlParse,
  /// Invalid field format
  InvalidFormat,
  /// Reference not found
  NotFound,
  /// Address parsing failed
  InvalidAddress,
  /// Address conflict between listeners
  AddressConflict,
}

/// Configuration validation error
#[derive(Debug, Clone)]
pub struct ConfigError {
  /// Error location (e.g. "services[0].kind")
  pub location: String,
  /// Error message
  pub message: String,
  /// Error kind
  pub kind: ConfigErrorKind,
}

impl std::fmt::Display for ConfigError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}: {}", self.location, self.message)
  }
}

impl std::error::Error for ConfigError {}

/// Error collector for configuration validation
pub struct ConfigErrorCollector {
  errors: Vec<ConfigError>,
}

impl ConfigErrorCollector {
  /// Create a new error collector
  pub fn new() -> Self {
    Self { errors: Vec::new() }
  }

  /// Add an error
  pub fn add(
    &mut self,
    location: impl Into<String>,
    message: impl Into<String>,
    kind: ConfigErrorKind,
  ) {
    self.errors.push(ConfigError {
      location: location.into(),
      message: message.into(),
      kind,
    });
  }

  /// Check if there are any errors
  pub fn has_errors(&self) -> bool {
    !self.errors.is_empty()
  }

  /// Get all errors
  pub fn errors(&self) -> &[ConfigError] {
    &self.errors
  }

  /// Print error report and exit with code 1
  pub fn report_and_exit(&self) -> ! {
    if self.errors.is_empty() {
      eprintln!("No configuration errors found.");
      process::exit(0);
    }

    eprintln!("Configuration errors:");
    for error in &self.errors {
      eprintln!("  {}: {}", error.location, error.message);
    }

    eprintln!();
    let error_count = self.errors.len();
    let error_word = if error_count == 1 { "error" } else { "errors" };
    eprintln!(
      "{} {} found. Please fix the configuration file.",
      error_count, error_word
    );
    process::exit(1);
  }
}

impl Default for ConfigErrorCollector {
  fn default() -> Self {
    Self::new()
  }
}

// =========================================================================
// Validation logic (moved from config.rs)
// =========================================================================

/// Validate worker_threads global setting.
pub fn validate_worker_threads(
  worker_threads: usize,
  collector: &mut ConfigErrorCollector,
) {
  if worker_threads == 0 {
    collector.add(
      "worker_threads",
      "must be at least 1".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
  }
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

/// Validate the entire configuration.
///
/// This function validates:
/// - Global settings (worker_threads)
/// - Kind format for all services and listeners
/// - Service references in servers
/// - Address parsing in listener args
/// - Listener TLS requirements
/// - Hostname patterns
/// - User configurations
/// - TLS configurations
/// - HTTP/3 specific configurations
/// - Address conflicts across servers
pub fn validate_config(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  // Validate global settings
  validate_worker_threads(config.worker_threads, collector);

  // Validate access_log if present
  if let Some(ref access_log) = config.access_log {
    validate_access_log_config(access_log, collector);
  }

  // Collect all service names for reference validation
  let service_names: HashSet<&str> =
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

    // Validate users if present
    if let Some(ref users) = server.users {
      validate_users(
        users,
        &format!("{}.users", server_location),
        collector,
      );
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

    // Validate listeners
    for (listener_idx, listener) in server.listeners.iter().enumerate()
    {
      let listener_location =
        format!("{}.listeners[{}]", server_location, listener_idx);
      validate_listener(
        listener,
        &listener_location,
        server.tls.as_ref(),
        collector,
      );
    }
  }

  // Validate SOCKS5 + hostnames semantic
  validate_socks5_hostnames(config, collector);

  // Validate address conflicts across all servers
  validate_address_conflicts(config, collector);
}

/// Validate that SOCKS5 listeners are not configured with hostnames.
fn validate_socks5_hostnames(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  for (server_idx, server) in config.servers.iter().enumerate() {
    if !server.hostnames.is_empty() {
      // Check if any listener is SOCKS5 (report error once per server)
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
    // Valid: "*.example.com" (must have dot after *)
    // Invalid: "*" (bare wildcard)
    // Invalid: "*example.com" (wildcard without dot separator)
    if !after_star.starts_with('.') || after_star.is_empty() {
      // bare "*" or "*" at end
      collector.add(
        location.to_string(),
        format!("invalid wildcard hostname '{}'", hostname),
        ConfigErrorKind::InvalidFormat,
      );
    } else {
      // after_star starts with ".", check suffix after dot
      let suffix = &after_star[1..];
      if suffix.is_empty() || !suffix.contains('.') {
        // "*.com" or "*.example" - need at least one more dot
        collector.add(
          location.to_string(),
          format!("invalid wildcard hostname '{}'", hostname),
          ConfigErrorKind::InvalidFormat,
        );
      }
    }
  }
}

/// Validate server-level users configuration.
pub fn validate_users(
  users: &[UserConfig],
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if users.is_empty() {
    collector.add(
      location.to_string(),
      "users cannot be an empty array".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
    return;
  }

  for (idx, user) in users.iter().enumerate() {
    let user_location = format!("{}[{}]", location, idx);

    if user.username.is_empty() {
      collector.add(
        format!("{}.username", user_location),
        "username cannot be empty".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }

    if user.password.is_empty() {
      collector.add(
        format!("{}.password", user_location),
        "password cannot be empty".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }
  }
}

/// Validate server-level TLS configuration.
pub fn validate_server_tls(
  tls: &ServerTlsConfig,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if tls.certificates.is_empty() {
    collector.add(
      format!("{}.certificates", location),
      "at least one certificate is required".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
    return;
  }

  for (idx, cert) in tls.certificates.iter().enumerate() {
    let cert_location = format!("{}.certificates[{}]", location, idx);

    // Validate cert path exists and is readable
    match fs::read_to_string(std::path::Path::new(&cert.cert_path)) {
      Ok(content) => {
        if !content.contains("-----BEGIN CERTIFICATE-----")
          && !content.contains("-----BEGIN TRUSTED CERTIFICATE-----")
        {
          collector.add(
            format!("{}.cert_path", cert_location),
            format!(
              "certificate file '{}' is not in PEM format",
              cert.cert_path
            ),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
      Err(e) => {
        collector.add(
          format!("{}.cert_path", cert_location),
          format!(
            "certificate file '{}' cannot be read: {}",
            cert.cert_path, e
          ),
          ConfigErrorKind::FileRead,
        );
      }
    }

    // Validate key path exists and is readable
    match fs::read_to_string(std::path::Path::new(&cert.key_path)) {
      Ok(content) => {
        if !content.contains("-----BEGIN PRIVATE KEY-----")
          && !content.contains("-----BEGIN RSA PRIVATE KEY-----")
          && !content.contains("-----BEGIN EC PRIVATE KEY-----")
          && !content.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        {
          collector.add(
            format!("{}.key_path", cert_location),
            format!(
              "private key file '{}' is not in PEM format",
              cert.key_path
            ),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
      Err(e) => {
        collector.add(
          format!("{}.key_path", cert_location),
          format!(
            "private key file '{}' cannot be read: {}",
            cert.key_path, e
          ),
          ConfigErrorKind::FileRead,
        );
      }
    }
  }
}

/// Validate HTTP/3 listener specific configuration.
///
/// Validates:
/// - QUIC parameters validity
///
/// Note: Address validation is handled by validate_listener_addresses.
/// Note: TLS and auth are now at server level, not listener level.
pub fn validate_http3_listener_args(
  args: &SerializedArgs,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  // Validate QUIC parameters
  if let Some(quic) = args.get("quic") {
    validate_quic_config(
      quic,
      &format!("{}.args.quic", location),
      collector,
    );
  }

  // Note: TLS and auth are no longer validated at listener level.
  // They are now at server level and validated in validate_server_tls and validate_users.
}

/// Validate QUIC configuration parameters.
///
/// Validates QUIC parameters and reports errors for invalid values.
/// Invalid parameters will cause startup to fail.
pub fn validate_quic_config(
  quic: &SerializedArgs,
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  // Validate max_concurrent_bidi_streams
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

  // Validate max_idle_timeout_ms
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

  // Validate initial_mtu
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

  // Validate send_window
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

  // Validate receive_window
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

/// Validate a server's service reference.
///
/// Checks that the server's service field references an existing service.
/// Empty service names are allowed (for servers without a service).
///
/// Note: This function validates the service *reference* from a server,
/// not the service configuration itself. Service configuration validation
/// (kind format, plugin existence) is handled at parse time and runtime.
pub fn validate_service(
  service_names: &std::collections::HashSet<&str>,
  server_idx: usize,
  service: &str,
  collector: &mut ConfigErrorCollector,
) {
  if !service.is_empty() && !service_names.contains(service) {
    collector.add(
      format!("servers[{}].service", server_idx),
      format!("service '{}' not found", service),
      ConfigErrorKind::NotFound,
    );
  }
}

/// Validate address conflicts across all servers and listeners.
///
/// Rules:
/// - Different transport layer (TCP vs UDP): NO CONFLICT
/// - Same transport layer, different kind: CONFLICT
/// - Same kind, supports hostname routing: ALLOWED (Task 020 handles routing)
/// - Same kind, NO hostname routing support (socks5): CONFLICT
/// - Multiple default servers (empty hostnames) on same address+kind: CONFLICT (CR-003)
pub fn validate_address_conflicts(
  config: &Config,
  collector: &mut ConfigErrorCollector,
) {
  let mut address_map: HashMap<SocketAddr, Vec<AddressUsage>> =
    HashMap::new();

  for server in &config.servers {
    for listener in &server.listeners {
      let category =
        match ListenerCategory::from_kind(&listener.listener_name) {
          Some(c) => c,
          None => continue, // Unknown kind - already validated elsewhere
        };

      // Get addresses from listener args
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
      continue; // No conflict possible
    }

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

    // Check TCP conflicts: different kinds = conflict
    if tcp_usages.len() > 1 {
      let kinds: HashSet<_> =
        tcp_usages.iter().map(|u| u.listener_kind.as_str()).collect();

      if kinds.len() > 1 {
        // Different TCP kinds on same address = conflict
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
        // Same TCP kind - check for multiple default servers (CR-003)
        check_hostname_routing_conflicts(&tcp_usages, addr, collector);
      }
    }

    // Check UDP conflicts: different kinds = conflict
    if udp_usages.len() > 1 {
      let kinds: HashSet<_> =
        udp_usages.iter().map(|u| u.listener_kind.as_str()).collect();

      if kinds.len() > 1 {
        // Different UDP kinds on same address = conflict
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
        // Same UDP kind - check for multiple default servers (CR-003)
        check_hostname_routing_conflicts(&udp_usages, addr, collector);
      }
    }
  }
}

/// Check for hostname routing conflicts sharing the same address+kind.
///
/// CR-003: Multiple default servers on same (address, kind) causes routing ambiguity.
/// Also detects exact hostname duplicates (case-insensitive, DNS rules).
pub fn check_hostname_routing_conflicts(
  usages: &[&AddressUsage],
  addr: SocketAddr,
  collector: &mut ConfigErrorCollector,
) {
  let mut default_servers: Vec<&str> = Vec::new();
  let mut hostname_map: HashMap<String, Vec<&str>> = HashMap::new();

  // Single pass to collect both conflict types
  for usage in usages {
    if usage.hostnames.is_empty() {
      default_servers.push(&usage.server_name);
    } else {
      for hostname in &usage.hostnames {
        let normalized = hostname.to_lowercase(); // DNS is case-insensitive
        hostname_map
          .entry(normalized)
          .or_default()
          .push(&usage.server_name);
      }
    }
  }

  // Check multiple default servers
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

  // Check hostname duplicates
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

/// Validate access log configuration (moved from AccessLogConfig::validate).
pub fn validate_access_log_config(
  access_log: &AccessLogConfig,
  collector: &mut ConfigErrorCollector,
) {
  use std::time::Duration;

  // Validate buffer minimum size (at least 1KB)
  if access_log.buffer.as_u64() < 1024 {
    collector.add(
      "access_log.buffer",
      format!(
        "buffer size must be at least 1KB, got {} bytes",
        access_log.buffer.as_u64()
      ),
      ConfigErrorKind::InvalidFormat,
    );
  }

  // Validate max_size minimum size (at least 1MB)
  if access_log.max_size.as_u64() < 1024 * 1024 {
    collector.add(
      "access_log.max_size",
      format!(
        "max_size must be at least 1MB, got {} bytes",
        access_log.max_size.as_u64()
      ),
      ConfigErrorKind::InvalidFormat,
    );
  }

  // Validate flush interval (at least 100ms)
  if access_log.flush.0 < Duration::from_millis(100) {
    collector.add(
      "access_log.flush",
      format!(
        "flush interval must be at least 100ms, got {:?}",
        access_log.flush.0
      ),
      ConfigErrorKind::InvalidFormat,
    );
  }

  // Validate path_prefix not empty
  if access_log.path_prefix.is_empty() {
    collector.add(
      "access_log.path_prefix",
      "path_prefix cannot be empty".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
  }
}

/// Validate listener authentication configuration (moved from
/// ListenerAuthConfig::validate).
///
/// Rules:
/// - At least one auth method (`users` or `client_ca_path`) must be configured
/// - Each username must be non-empty, <= 255 bytes, and unique
pub fn validate_listener_auth_config(
  auth: &ListenerAuthConfig,
  collector: &mut ConfigErrorCollector,
) {
  // At least one auth method must be configured
  if auth.users.is_empty() && auth.client_ca_path.is_none() {
    collector.add(
      "auth",
      "auth config must have at least 'users' or 'client_ca_path'"
        .to_string(),
      ConfigErrorKind::InvalidFormat,
    );
    return;
  }

  // Validate users
  let mut seen_users = std::collections::HashSet::new();
  for (idx, user) in auth.users.iter().enumerate() {
    let user_location = format!("auth.users[{}]", idx);

    if user.username.is_empty() {
      collector.add(
        format!("{}.username", user_location),
        "username cannot be empty".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }

    if user.username.len() > 255 {
      collector.add(
        format!("{}.username", user_location),
        format!(
          "username '{}' is too long (max 255 bytes)",
          user.username
        ),
        ConfigErrorKind::InvalidFormat,
      );
    }

    if !seen_users.insert(user.username.clone()) {
      collector.add(
        format!("{}.username", user_location),
        format!(
          "duplicate username '{}' found in users list",
          user.username
        ),
        ConfigErrorKind::InvalidFormat,
      );
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{ListenerAuthConfig, UserCredential};
  use crate::config::{Server, Service};

  #[test]
  fn test_config_error_display() {
    let error = ConfigError {
      location: "services[0].kind".to_string(),
      message: "invalid format".to_string(),
      kind: ConfigErrorKind::InvalidFormat,
    };
    assert_eq!(
      format!("{}", error),
      "services[0].kind: invalid format"
    );
  }

  #[test]
  fn test_config_error_kind_equality() {
    assert_eq!(ConfigErrorKind::FileRead, ConfigErrorKind::FileRead);
    assert_eq!(
      ConfigErrorKind::InvalidFormat,
      ConfigErrorKind::InvalidFormat
    );
    assert_ne!(ConfigErrorKind::FileRead, ConfigErrorKind::YamlParse);
  }

  #[test]
  fn test_error_collector_new() {
    let collector = ConfigErrorCollector::new();
    assert!(!collector.has_errors());
    assert!(collector.errors().is_empty());
  }

  #[test]
  fn test_error_collector_default() {
    let collector = ConfigErrorCollector::default();
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_error_collector_add_single_error() {
    let mut collector = ConfigErrorCollector::new();
    collector.add(
      "services[0].kind",
      "plugin 'unknown_plugin' not found",
      ConfigErrorKind::NotFound,
    );

    assert!(collector.has_errors());
    assert_eq!(collector.errors().len(), 1);

    let error = &collector.errors()[0];
    assert_eq!(error.location, "services[0].kind");
    assert_eq!(error.message, "plugin 'unknown_plugin' not found");
    assert_eq!(error.kind, ConfigErrorKind::NotFound);
  }

  #[test]
  fn test_error_collector_add_multiple_errors() {
    let mut collector = ConfigErrorCollector::new();

    collector.add(
      "services[0].kind",
      "plugin 'unknown_plugin' not found",
      ConfigErrorKind::NotFound,
    );
    collector.add(
      "servers[0].listeners[0].kind",
      "listener builder 'http' not found",
      ConfigErrorKind::NotFound,
    );

    assert!(collector.has_errors());
    assert_eq!(collector.errors().len(), 2);
  }

  #[test]
  fn test_error_collector_add_with_string_types() {
    let mut collector = ConfigErrorCollector::new();
    let location = String::from("services[0].kind");
    let message = String::from("error message");

    collector.add(location, message, ConfigErrorKind::InvalidFormat);

    assert!(collector.has_errors());
    assert_eq!(collector.errors()[0].location, "services[0].kind");
    assert_eq!(collector.errors()[0].message, "error message");
  }

  #[test]
  fn test_error_collector_errors_slice() {
    let mut collector = ConfigErrorCollector::new();
    collector.add("loc1", "msg1", ConfigErrorKind::InvalidFormat);
    collector.add("loc2", "msg2", ConfigErrorKind::InvalidFormat);

    let errors = collector.errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].location, "loc1");
    assert_eq!(errors[1].location, "loc2");
  }

  #[test]
  fn test_config_error_is_error() {
    fn assert_error<E: std::error::Error>() {}
    assert_error::<ConfigError>();
  }

  #[test]
  fn test_config_error_debug() {
    let error = ConfigError {
      location: "test".to_string(),
      message: "test message".to_string(),
      kind: ConfigErrorKind::InvalidFormat,
    };
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("ConfigError"));
    assert!(debug_str.contains("test"));
  }

  #[test]
  fn test_config_error_kind_debug() {
    let kind = ConfigErrorKind::InvalidFormat;
    let debug_str = format!("{:?}", kind);
    assert!(debug_str.contains("InvalidFormat"));
  }

  #[test]
  fn test_error_collector_all_error_kinds() {
    let mut collector = ConfigErrorCollector::new();

    collector.add("loc1", "msg1", ConfigErrorKind::FileRead);
    collector.add("loc2", "msg2", ConfigErrorKind::YamlParse);
    collector.add("loc3", "msg3", ConfigErrorKind::InvalidFormat);
    collector.add("loc4", "msg4", ConfigErrorKind::NotFound);
    collector.add("loc5", "msg5", ConfigErrorKind::InvalidAddress);
    collector.add("loc6", "msg6", ConfigErrorKind::AddressConflict);

    assert_eq!(collector.errors().len(), 6);
    assert!(collector.has_errors());

    assert_eq!(collector.errors()[0].kind, ConfigErrorKind::FileRead);
    assert_eq!(collector.errors()[1].kind, ConfigErrorKind::YamlParse);
    assert_eq!(
      collector.errors()[2].kind,
      ConfigErrorKind::InvalidFormat
    );
    assert_eq!(collector.errors()[3].kind, ConfigErrorKind::NotFound);
    assert_eq!(
      collector.errors()[4].kind,
      ConfigErrorKind::InvalidAddress
    );
    assert_eq!(
      collector.errors()[5].kind,
      ConfigErrorKind::AddressConflict
    );
  }

  // =========================================================================
  // validate_config Tests
  // =========================================================================

  #[test]
  fn test_validate_config_valid() {
    let config = Config {
      services: vec![Service {
        name: "echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![crate::config::Server {
        name: "server1".to_string(),
        hostnames: vec![],
        listeners: vec![crate::config::Listener {
          listener_name: "http".to_string(),
          args: serde_yaml::from_str(
            r#"{addresses: ["127.0.0.1:8080"]}"#,
          )
          .unwrap(),
        }],
        service: "echo".to_string(),
        tls: None,
        users: None,
        access_log: None,
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "Valid config should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_config_empty() {
    let config = Config::default();
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_config_worker_threads_zero() {
    let config = Config { worker_threads: 0, ..Default::default() };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "worker_threads" && e.message.contains("at least 1")
    });
    assert!(found, "Should have worker_threads validation error");
  }

  #[test]
  fn test_validate_config_service_reference_not_found() {
    let config = Config {
      services: vec![],
      servers: vec![crate::config::Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(
      errors[0].message.contains("service 'nonexistent' not found")
    );
  }

  #[test]
  fn test_validate_config_invalid_listener_address() {
    let config = Config {
      servers: vec![crate::config::Server {
        name: "test".to_string(),
        listeners: vec![crate::config::Listener {
          listener_name: "http".to_string(),
          args: serde_yaml::from_str(
            r#"{addresses: ["invalid:address"]}"#,
          )
          .unwrap(),
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_config_https_without_tls() {
    let config = Config {
      servers: vec![crate::config::Server {
        name: "https_server".to_string(),
        listeners: vec![crate::config::Listener {
          listener_name: "https".to_string(),
          args: serde_yaml::from_str(
            r#"{addresses: ["127.0.0.1:8443"]}"#,
          )
          .unwrap(),
        }],
        service: "".to_string(),
        tls: None,
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(found, "Should have TLS required error for https");
  }

  // =========================================================================
  // Address Conflict Detection Tests
  // =========================================================================

  /// Helper function to check if error message contains a substring
  fn has_error_containing(
    collector: &ConfigErrorCollector,
    substring: &str,
  ) -> bool {
    collector.errors().iter().any(|e| e.message.contains(substring))
  }

  #[test]
  fn test_address_conflict_tcp_vs_tcp_different_kind() {
    // Two listeners of different TCP kinds on same address should conflict
    let args1 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = Config {
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
        crate::config::Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "http".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        crate::config::Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "socks5".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    assert!(has_error_containing(&collector, "address conflict"));
  }

  #[test]
  fn test_address_no_conflict_tcp_vs_udp() {
    // HTTP (TCP) and HTTP/3 (UDP) on same address should NOT conflict
    use crate::config::{CertificateConfig, ServerTlsConfig};

    // Install CryptoProvider for TLS validation
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#)
        .unwrap();

    let config = Config {
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
      servers: vec![crate::config::Server {
        name: "server1".to_string(),
        hostnames: vec![],
        tls: Some(ServerTlsConfig {
          certificates: vec![CertificateConfig {
            cert_path: "conf/certs/server.crt".to_string(),
            key_path: "conf/certs/server.key".to_string(),
          }],
          client_ca_certs: None,
        }),
        users: None,
        listeners: vec![
          crate::config::Listener {
            listener_name: "http".to_string(),
            args: args.clone(),
          },
          crate::config::Listener {
            listener_name: "http3".to_string(),
            args: args,
          },
        ],
        service: "echo".to_string(),
        access_log: None,
      }],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    // Should NOT have address conflict errors (may have other errors like missing cert files)
    let has_address_conflict =
      has_error_containing(&collector, "address conflict");
    assert!(
      !has_address_conflict,
      "Expected no address conflict, but found one"
    );
  }

  #[test]
  fn test_address_same_kind_can_share_with_hostnames() {
    // Same kind (http) CAN share address when they support hostname routing
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = Config {
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
        crate::config::Server {
          name: "default_server".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "http".to_string(),
            args: args.clone(),
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        crate::config::Server {
          name: "api_server".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "http".to_string(),
            args: args,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    // Should be VALID - same kind with hostname routing can share address
    assert!(
      !collector.has_errors(),
      "Expected no errors but found: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_address_socks5_cannot_share() {
    // socks5 does NOT support hostname routing, so multiple socks5 on same address = CONFLICT
    // This is now caught by the "multiple default servers" check (Task 003)
    // since SOCKS5 servers have empty hostnames and are treated as default servers
    let args1 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let args2 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();

    let config = Config {
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
        crate::config::Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "socks5".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        crate::config::Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "socks5".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    // SOCKS5 conflict is now caught by "multiple default servers" check
    assert!(has_error_containing(
      &collector,
      "multiple default servers"
    ));
  }

  #[test]
  fn test_address_multiple_http_no_hostnames_conflict() {
    // CR-003: Multiple default servers (empty hostnames) on same address+kind should cause error
    // This causes routing ambiguity - when no Host header matches, which default server handles the request?
    let args1 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();

    let config = Config {
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
        crate::config::Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "http".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        crate::config::Server {
          name: "server2".to_string(),
          hostnames: vec![],
          tls: None,
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "http".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    // CR-003: This should be an error - multiple default servers on same address
    assert!(
      collector.has_errors(),
      "Expected error for multiple default servers on same address"
    );
    assert!(
      has_error_containing(&collector, "multiple default servers"),
      "Error should mention multiple default servers"
    );
  }

  #[test]
  fn test_address_udp_vs_udp_conflict() {
    // Two HTTP/3 listeners on same address should NOT conflict if they support hostname routing
    // (similar to TCP case - same kind can share with hostname routing)
    use crate::config::{CertificateConfig, ServerTlsConfig};

    // Install CryptoProvider for TLS validation
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args1 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#)
        .unwrap();
    let args2 =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#)
        .unwrap();

    let config = Config {
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
        crate::config::Server {
          name: "server1".to_string(),
          hostnames: vec![],
          tls: Some(ServerTlsConfig {
            certificates: vec![CertificateConfig {
              cert_path: "conf/certs/server.crt".to_string(),
              key_path: "conf/certs/server.key".to_string(),
            }],
            client_ca_certs: None,
          }),
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "http3".to_string(),
            args: args1,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
        crate::config::Server {
          name: "server2".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          tls: Some(ServerTlsConfig {
            certificates: vec![CertificateConfig {
              cert_path: "conf/certs/server.crt".to_string(),
              key_path: "conf/certs/server.key".to_string(),
            }],
            client_ca_certs: None,
          }),
          users: None,
          listeners: vec![crate::config::Listener {
            listener_name: "http3".to_string(),
            args: args2,
          }],
          service: "echo".to_string(),
          access_log: None,
        },
      ],
    };

    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    // Same UDP kind with hostname routing support is allowed
    // (may have cert file errors but should not have address conflict)
    let has_address_conflict =
      has_error_containing(&collector, "address conflict");
    assert!(
      !has_address_conflict,
      "Expected no address conflict for same UDP kind with hostname routing"
    );
  }

  // =========================================================================
  // validate_listener_auth_config Tests
  // =========================================================================

  #[test]
  fn test_validate_listener_auth_config_empty_is_error() {
    let config = ListenerAuthConfig::default();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(
      collector.has_errors(),
      "Empty auth config should produce error"
    );
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message
        .contains("must have at least 'users' or 'client_ca_path'")
    });
    assert!(found, "Should have 'at least one method' error");
  }

  #[test]
  fn test_validate_listener_auth_config_password_only_ok() {
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "Password-only config should be valid"
    );
  }

  #[test]
  fn test_validate_listener_auth_config_tls_only_ok() {
    let config = ListenerAuthConfig {
      users: vec![],
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(!collector.has_errors(), "TLS-only config should be valid");
  }

  #[test]
  fn test_validate_listener_auth_config_duplicate_username_is_error() {
    let config = ListenerAuthConfig {
      users: vec![
        UserCredential {
          username: "admin".to_string(),
          password: "pass1".to_string(),
        },
        UserCredential {
          username: "admin".to_string(),
          password: "pass2".to_string(),
        },
      ],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(
      collector.has_errors(),
      "Duplicate usernames should be invalid"
    );
    let errors = collector.errors();
    let found =
      errors.iter().any(|e| e.message.contains("duplicate username"));
    assert!(found, "Should have duplicate username error");
  }

  #[test]
  fn test_validate_listener_auth_config_empty_username_is_error() {
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: "".to_string(),
        password: "pass".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors(), "Empty username should be invalid");
    let errors = collector.errors();
    let found = errors
      .iter()
      .any(|e| e.message.contains("username cannot be empty"));
    assert!(found, "Should have empty username error");
  }

  // =========================================================================
  // validate_worker_threads Tests
  // =========================================================================

  #[test]
  fn test_validate_worker_threads_zero_standalone() {
    let mut collector = ConfigErrorCollector::new();
    validate_worker_threads(0, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "worker_threads" && e.message.contains("at least 1")
    });
    assert!(found, "Should have worker_threads validation error");
  }

  #[test]
  fn test_validate_worker_threads_one_standalone() {
    let mut collector = ConfigErrorCollector::new();
    validate_worker_threads(1, &mut collector);
    assert!(
      !collector.has_errors(),
      "worker_threads=1 should be valid"
    );
  }

  #[test]
  fn test_validate_empty_config() {
    let config = Config::default();
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_valid_service() {
    let config = Config {
      services: vec![Service {
        name: "test_echo".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_valid_listener() {
    let args =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_service_reference_not_found() {
    let config = Config {
      services: vec![],
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(
      errors[0].message.contains("service 'nonexistent' not found")
    );
  }

  #[test]
  fn test_validate_service_reference_found() {
    let config = Config {
      services: vec![Service {
        name: "existing".to_string(),
        plugin_name: "echo".to_string(),
        service_name: "echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "existing".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_valid_address() {
    let args =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_address() {
    let args =
      serde_yaml::from_str(r#"{addresses: ["invalid:address"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
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
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
    assert_eq!(errors[1].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_multiple_services_and_listeners() {
    let listener_args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let listener_args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8081"]}"#)
        .unwrap();
    let config = Config {
      services: vec![
        Service {
          name: "echo".to_string(),
          plugin_name: "echo".to_string(),
          service_name: "echo".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
        Service {
          name: "connect".to_string(),
          plugin_name: "connect_tcp".to_string(),
          service_name: "connect_tcp".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
      ],
      servers: vec![
        Server {
          name: "server1".to_string(),
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: listener_args1,
          }],
          service: "echo".to_string(),
          ..Default::default()
        },
        Server {
          name: "server2".to_string(),
          listeners: vec![Listener {
            listener_name: "http".to_string(),
            args: listener_args2,
          }],
          service: "connect".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_multiple_errors() {
    // Multiple invalid addresses should produce multiple errors
    let args = serde_yaml::from_str(
      r#"{addresses: ["invalid1", "127.0.0.1:8080", "invalid2"]}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    // 2 invalid address errors
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
    assert_eq!(errors[1].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_empty_service_name() {
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![],
        service: "".to_string(), // empty service name should be allowed
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_addresses_empty_array() {
    let args = serde_yaml::from_str(r#"{addresses: []}"#).unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    // Empty addresses list is an error
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors
      .iter()
      .any(|e| e.message.contains("addresses list cannot be empty"));
    assert!(found, "Should have empty addresses error");
  }

  #[test]
  fn test_validate_socks5_with_hostnames_error() {
    // SOCKS5 + hostnames should be a semantic error
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "socks_server".to_string(),
        hostnames: vec!["api.example.com".to_string()], // Invalid with SOCKS5
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
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert!(!errors.is_empty());
    // Should have error about hostnames with SOCKS5
    let found = errors.iter().any(|e| {
      e.message.contains("hostnames cannot be configured with SOCKS5")
    });
    assert!(found, "Should have SOCKS5 hostname error");
  }

  #[test]
  fn test_validate_socks5_without_hostnames_ok() {
    // SOCKS5 without hostnames should be OK
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "socks_server".to_string(),
        hostnames: vec![], // Empty is OK
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
    validate_config(&config, &mut collector);
    // Should NOT have errors about SOCKS5 hostnames
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message.contains("hostnames cannot be configured with SOCKS5")
    });
    assert!(!found, "Should not have SOCKS5 hostname error");
  }

  #[test]
  fn test_validate_http_with_hostnames_ok() {
    // HTTP with hostnames should be OK
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "http_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_socks5_hostname_error_location_uses_index() {
    // CR-001: Error location should use index format, not server name
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
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
    validate_config(&config, &mut collector);
    let errors = collector.errors();
    assert!(!errors.is_empty());
    // Location should use index format "servers[0]" not name format "servers[socks_server]"
    let error = errors
      .iter()
      .find(|e| {
        e.message.contains("hostnames cannot be configured with SOCKS5")
      })
      .expect("Should have SOCKS5 hostname error");
    assert_eq!(
      error.location, "servers[0]",
      "Location should use index format, not name format"
    );
  }

  #[test]
  fn test_validate_socks5_multiple_listeners_single_error() {
    // CR-002: Multiple SOCKS5 listeners should produce only one error
    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1081"]}"#)
        .unwrap();
    let args3: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1082"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "socks_server".to_string(),
        hostnames: vec!["api.example.com".to_string()],
        listeners: vec![
          Listener { listener_name: "socks5".to_string(), args: args1 },
          Listener { listener_name: "socks5".to_string(), args: args2 },
          Listener { listener_name: "socks5".to_string(), args: args3 },
        ],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    let errors = collector.errors();
    // Count SOCKS5 hostname errors - should be exactly 1, not 3
    let socks5_hostname_errors: Vec<_> = errors
      .iter()
      .filter(|e| {
        e.message.contains("hostnames cannot be configured with SOCKS5")
      })
      .collect();
    assert_eq!(
      socks5_hostname_errors.len(),
      1,
      "Should have exactly one SOCKS5 hostname error, not one per listener"
    );
  }

  #[test]
  fn test_validate_exact_hostname_duplicate_conflict() {
    // Two servers with same hostname on same address = conflict
    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
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
          hostnames: vec!["api.example.com".to_string()], // Duplicate!
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
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message
        .contains("'api.example.com' defined in multiple servers")
    });
    assert!(found, "Should have hostname conflict error");
  }

  #[test]
  fn test_validate_hostname_case_insensitive_conflict() {
    // Same hostname different case = conflict (DNS is case-insensitive)
    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
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
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message
        .contains("'api.example.com' defined in multiple servers")
    });
    assert!(
      found,
      "Should have case-insensitive hostname conflict error"
    );
  }

  #[test]
  fn test_validate_wildcard_duplicate_conflict() {
    // Two servers with same wildcard on same address = conflict
    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
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
          hostnames: vec!["*.example.com".to_string()], // Duplicate wildcard!
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
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message.contains("'*.example.com' defined in multiple servers")
    });
    assert!(found, "Should have wildcard conflict error");
  }

  #[test]
  fn test_validate_wildcard_and_exact_no_conflict() {
    // Wildcard + exact hostname = NO conflict (exact match takes precedence)
    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
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
          hostnames: vec!["api.example.com".to_string()], // Exact match, OK
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
    validate_config(&config, &mut collector);
    // Should NOT have hostname conflict errors
    let errors = collector.errors();
    let found = errors
      .iter()
      .any(|e| e.message.contains("defined in multiple servers"));
    assert!(!found, "Wildcard + exact should not be a conflict");
  }

  #[test]
  fn test_validate_different_hostnames_no_conflict() {
    // Multiple servers with different hostnames = OK
    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
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
    validate_config(&config, &mut collector);
    // Should NOT have hostname conflict errors
    let errors = collector.errors();
    let found = errors
      .iter()
      .any(|e| e.message.contains("defined in multiple servers"));
    assert!(!found, "Different hostnames should not be a conflict");
  }

  #[test]
  fn test_validate_multiple_socks5_same_address_conflict() {
    // Multiple SOCKS5 on same address = conflict (via default server check)
    let args1: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let args2: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:1080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![
        Server {
          name: "socks_a".to_string(),
          hostnames: vec![], // SOCKS5 has no hostnames
          listeners: vec![Listener {
            listener_name: "socks5".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "socks_b".to_string(),
          hostnames: vec![], // SOCKS5 has no hostnames
          listeners: vec![Listener {
            listener_name: "socks5".to_string(),
            args: args2,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    // Should have "multiple default servers" error (SOCKS5 treated as default)
    let found = errors
      .iter()
      .any(|e| e.message.contains("multiple default servers"));
    assert!(
      found,
      "Should have multiple default servers error for SOCKS5"
    );
  }

  #[test]
  fn test_validate_worker_threads_zero_is_error() {
    let config = Config { worker_threads: 0, ..Default::default() };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.location == "worker_threads" && e.message.contains("at least 1")
    });
    assert!(found, "Should have worker_threads validation error");
  }

  #[test]
  fn test_validate_worker_threads_one_is_valid() {
    let config = Config { worker_threads: 1, ..Default::default() };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "worker_threads=1 should be valid"
    );
  }

  #[test]
  fn test_validate_https_without_tls_is_error() {
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "https_server".to_string(),
        listeners: vec![Listener {
          listener_name: "https".to_string(),
          args,
        }],
        service: "".to_string(),
        tls: None, // Missing TLS!
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(found, "Should have TLS required error for https");
  }

  #[test]
  fn test_validate_http3_without_tls_is_error() {
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8443"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "http3_server".to_string(),
        listeners: vec![Listener {
          listener_name: "http3".to_string(),
          args,
        }],
        service: "".to_string(),
        tls: None, // Missing TLS!
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(found, "Should have TLS required error for http3");
  }

  #[test]
  fn test_validate_http_without_tls_is_valid() {
    let args: serde_yaml::Value =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "http_server".to_string(),
        listeners: vec![Listener {
          listener_name: "http".to_string(),
          args,
        }],
        service: "".to_string(),
        tls: None, // HTTP doesn't need TLS
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_config(&config, &mut collector);
    // Should NOT have TLS required error (may have other errors like missing service)
    let errors = collector.errors();
    let found = errors.iter().any(|e| {
      e.message.contains("requires server-level 'tls' configuration")
    });
    assert!(!found, "HTTP should not require TLS");
  }

  // =========================================================================
  // validate_quic_config Tests (CR-008)
  // =========================================================================

  #[test]
  fn test_validate_quic_config_valid() {
    let quic = serde_yaml::from_str(
      r#"{
        max_concurrent_bidi_streams: 100,
        max_idle_timeout_ms: 30000,
        initial_mtu: 1200,
        send_window: 1048576,
        receive_window: 1048576
      }"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "Valid QUIC config should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_quic_config_empty() {
    let quic: serde_yaml::Value = serde_yaml::from_str("{}").unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "Empty QUIC config should be valid"
    );
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
    assert!(found, "Should reject bidi_streams=0");
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
    assert!(found, "Should reject bidi_streams=10001");
  }

  #[test]
  fn test_validate_quic_config_bidi_streams_boundary_low() {
    // Boundary: value 1 should be valid (start of range)
    let quic =
      serde_yaml::from_str(r#"{max_concurrent_bidi_streams: 1}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "bidi_streams=1 should be valid: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_quic_config_bidi_streams_boundary_high() {
    // Boundary: value 10000 should be valid (end of range)
    let quic =
      serde_yaml::from_str(r#"{max_concurrent_bidi_streams: 10000}"#)
        .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "bidi_streams=10000 should be valid: {:?}",
      collector.errors()
    );
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
    assert!(found, "Should reject idle_timeout=0");
  }

  #[test]
  fn test_validate_quic_config_idle_timeout_valid() {
    let quic =
      serde_yaml::from_str(r#"{max_idle_timeout_ms: 1}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "idle_timeout=1 should be valid: {:?}",
      collector.errors()
    );
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
    assert!(found, "Should reject initial_mtu=1199");
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
    assert!(found, "Should reject initial_mtu=9001");
  }

  #[test]
  fn test_validate_quic_config_initial_mtu_boundary_low() {
    let quic = serde_yaml::from_str(r#"{initial_mtu: 1200}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "initial_mtu=1200 should be valid: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_quic_config_initial_mtu_boundary_high() {
    let quic = serde_yaml::from_str(r#"{initial_mtu: 9000}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "initial_mtu=9000 should be valid: {:?}",
      collector.errors()
    );
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
    assert!(found, "Should reject send_window=0");
  }

  #[test]
  fn test_validate_quic_config_send_window_valid() {
    let quic = serde_yaml::from_str(r#"{send_window: 1}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "send_window=1 should be valid: {:?}",
      collector.errors()
    );
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
    assert!(found, "Should reject receive_window=0");
  }

  #[test]
  fn test_validate_quic_config_receive_window_valid() {
    let quic = serde_yaml::from_str(r#"{receive_window: 1}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(
      !collector.has_errors(),
      "receive_window=1 should be valid: {:?}",
      collector.errors()
    );
  }

  // =========================================================================
  // validate_hostname Tests (CR-010)
  // =========================================================================

  #[test]
  fn test_validate_hostname_empty_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("", "test.hostname", &mut collector);
    assert!(
      collector.has_errors(),
      "Empty hostname should be rejected"
    );
    let found = collector.errors().iter().any(|e| {
      e.location == "test.hostname"
        && e.message.contains("hostname cannot be empty")
    });
    assert!(found, "Should have empty hostname error");
  }

  #[test]
  fn test_validate_hostname_valid_exact() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname(
      "api.example.com",
      "test.hostname",
      &mut collector,
    );
    assert!(
      !collector.has_errors(),
      "Valid exact hostname should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_hostname_valid_single_label() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("localhost", "test.hostname", &mut collector);
    assert!(
      !collector.has_errors(),
      "Single-label hostname should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_hostname_valid_wildcard() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("*.example.com", "test.hostname", &mut collector);
    assert!(
      !collector.has_errors(),
      "Valid wildcard '*.example.com' should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_hostname_bare_wildcard_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("*", "test.hostname", &mut collector);
    assert!(
      collector.has_errors(),
      "Bare wildcard '*' should be rejected"
    );
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("invalid wildcard hostname"));
    assert!(found, "Should have invalid wildcard error");
  }

  #[test]
  fn test_validate_hostname_wildcard_no_dot_is_error() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname("*example.com", "test.hostname", &mut collector);
    assert!(
      collector.has_errors(),
      "Wildcard '*example.com' (no dot) should be rejected"
    );
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("invalid wildcard hostname"));
    assert!(found, "Should have invalid wildcard error");
  }

  #[test]
  fn test_validate_hostname_wildcard_with_subdomain_is_valid() {
    let mut collector = ConfigErrorCollector::new();
    validate_hostname(
      "*.sub.example.com",
      "test.hostname",
      &mut collector,
    );
    assert!(
      !collector.has_errors(),
      "Wildcard '*.sub.example.com' should be valid: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_quic_config_multiple_errors() {
    let quic = serde_yaml::from_str(
      r#"{
        max_concurrent_bidi_streams: 0,
        max_idle_timeout_ms: 0,
        initial_mtu: 500,
        send_window: 0,
        receive_window: 0
      }"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_quic_config(&quic, "test.quic", &mut collector);
    assert!(collector.has_errors());
    assert_eq!(
      collector.errors().len(),
      5,
      "Should report all 5 errors"
    );
  }

  // =========================================================================
  // validate_http3_listener_args Tests (CR-008)
  // =========================================================================

  #[test]
  fn test_validate_http3_listener_args_no_quic() {
    let args = serde_yaml::from_str(r#"{}"#).unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_http3_listener_args(&args, "test", &mut collector);
    assert!(
      !collector.has_errors(),
      "HTTP/3 args without quic should be valid: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_http3_listener_args_valid_quic() {
    let args = serde_yaml::from_str(
      r#"{quic: {max_concurrent_bidi_streams: 100, initial_mtu: 1200}}"#,
    )
    .unwrap();
    let mut collector = ConfigErrorCollector::new();
    validate_http3_listener_args(&args, "test", &mut collector);
    assert!(
      !collector.has_errors(),
      "Valid QUIC args should pass: {:?}",
      collector.errors()
    );
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
    assert!(found, "Should propagate QUIC validation error");
  }

  // =========================================================================
  // validate_service Tests (SR-006)
  // =========================================================================

  #[test]
  fn test_validate_service_direct_not_found() {
    let service_names: std::collections::HashSet<&str> =
      std::collections::HashSet::new();
    let mut collector = ConfigErrorCollector::new();
    validate_service(&service_names, 0, "nonexistent", &mut collector);
    assert!(
      collector.has_errors(),
      "Nonexistent service reference should produce error"
    );
    let found = collector.errors().iter().any(|e| {
      e.kind == ConfigErrorKind::NotFound
        && e.message.contains("service 'nonexistent' not found")
    });
    assert!(found, "Should have NotFound error for missing service");
  }

  #[test]
  fn test_validate_service_direct_found() {
    let mut service_names: std::collections::HashSet<&str> =
      std::collections::HashSet::new();
    service_names.insert("echo");
    let mut collector = ConfigErrorCollector::new();
    validate_service(&service_names, 0, "echo", &mut collector);
    assert!(
      !collector.has_errors(),
      "Existing service reference should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_service_direct_empty_name() {
    let service_names: std::collections::HashSet<&str> =
      std::collections::HashSet::new();
    let mut collector = ConfigErrorCollector::new();
    validate_service(&service_names, 0, "", &mut collector);
    assert!(
      !collector.has_errors(),
      "Empty service name should be allowed: {:?}",
      collector.errors()
    );
  }
}
