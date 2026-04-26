use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

use crate::access_log::{AccessLogConfig, AccessLogOverride};
use crate::config_validator::{
  ConfigErrorCollector, ConfigErrorKind, parse_kind,
};
use crate::listeners::ListenerBuilderSet;
use crate::plugin::SerializedArgs;
use crate::plugins::PluginBuilderSet;

#[derive(Parser, Debug)]
pub struct CmdOpt {
  /// Sets a custom config file
  #[arg(
    short,
    long = "config",
    value_name = "CONFIG_FILE",
    default_value_t = String::from("conf/server.yaml")
  )]
  pub config_file: String,

  /// Gets version
  #[arg(short, long = "version")]
  pub version: bool,
}

impl CmdOpt {
  pub fn global() -> &'static LazyLock<CmdOpt> {
    static CMD_OPT: LazyLock<CmdOpt> = LazyLock::new(CmdOpt::parse);
    &CMD_OPT
  }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Listener {
  pub kind: String,
  pub args: SerializedArgs,
}

/// Certificate configuration (cert + key pair)
#[derive(Deserialize, Clone, Debug)]
pub struct CertificateConfig {
  /// Path to certificate file (PEM format)
  pub cert_path: String,
  /// Path to private key file (PEM format)
  pub key_path: String,
}

/// Server-level TLS configuration
#[derive(Deserialize, Clone, Debug)]
pub struct ServerTlsConfig {
  /// List of certificates (cert_path + key_path pairs)
  pub certificates: Vec<CertificateConfig>,
  /// Optional client CA certificates for mTLS
  #[serde(default)]
  pub client_ca_certs: Option<Vec<String>>,
}

/// User credential configuration
#[derive(Deserialize, Clone, Debug)]
pub struct UserConfig {
  /// Username for authentication
  pub username: String,
  /// Password for authentication
  pub password: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Server {
  pub name: String,
  /// Virtual hostnames for this server (for SNI/Host routing)
  #[serde(default)]
  pub hostnames: Vec<String>,
  /// TLS configuration (for https and http3 listeners)
  pub tls: Option<ServerTlsConfig>,
  /// User authentication configuration
  #[serde(default)]
  pub users: Option<Vec<UserConfig>>,
  pub listeners: Vec<Listener>,
  pub service: String,
  #[serde(default)]
  pub access_log: Option<AccessLogOverride>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Layer {
  pub kind: String,
  // delegate the deserializition to layer factories
  pub args: SerializedArgs,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Service {
  pub name: String,
  pub kind: String,
  // delegate the deserializition to service factories.
  pub args: SerializedArgs,
  pub layers: Vec<Layer>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
  pub worker_threads: usize,
  pub log_directory: String,
  #[serde(default)]
  pub access_log: Option<AccessLogConfig>,
  pub services: Vec<Service>,
  pub servers: Vec<Server>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      worker_threads: 1,
      log_directory: String::from("logs/"),
      access_log: None,
      services: vec![],
      servers: vec![],
    }
  }
}

/// Transport layer type for address conflict detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TransportLayer {
  Tcp,
  Udp,
}

/// Listener kind category for conflict detection.
/// Includes whether the listener supports hostname-based routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ListenerCategory {
  Http,   // http listener - TCP, supports hostname routing
  Https,  // https listener - TCP, supports hostname routing
  Http3,  // http3 listener - UDP, supports hostname routing
  Socks5, // socks5 listener - TCP, NO hostname routing
}

impl ListenerCategory {
  fn from_kind(kind: &str) -> Option<Self> {
    match kind {
      "http" => Some(Self::Http),
      "https" => Some(Self::Https),
      "http3" => Some(Self::Http3),
      "socks5" => Some(Self::Socks5),
      _ => None,
    }
  }

  fn transport_layer(&self) -> TransportLayer {
    match self {
      Self::Http | Self::Https | Self::Socks5 => TransportLayer::Tcp,
      Self::Http3 => TransportLayer::Udp,
    }
  }
}

/// Address usage info for conflict detection.
struct AddressUsage {
  server_name: String,
  listener_kind: String,
  listener_category: ListenerCategory,
  /// Hostnames for this server (empty = default server)
  hostnames: Vec<String>,
}

impl Config {
  /// Parse config from a string
  pub fn parse_string(&mut self, s: &str) -> Result<()> {
    let de = serde_yaml::Deserializer::from_str(s);
    Deserialize::deserialize_in_place(de, self)
      .with_context(|| "parse config text failed".to_string())?;
    Ok(())
  }

  /// Read and parse config from a file
  fn parse_file(&mut self, path: &str) -> Result<()> {
    let s = fs::read_to_string(std::path::Path::new(path))
      .with_context(|| format!("read config file '{}'", path))?;
    self.parse_string(&s)?;
    Ok(())
  }

  /// Validate the configuration
  ///
  /// This method validates:
  /// - Kind format for all services and listeners
  /// - Plugin existence for all kinds
  /// - Service/listener builder existence in plugins
  /// - Service references in servers
  /// - Address parsing in listener args
  /// - Args parsing for all services and listeners
  pub fn validate(&self, collector: &mut ConfigErrorCollector) {
    // Collect all service names for reference validation
    let service_names: HashSet<&str> =
      self.services.iter().map(|s| s.name.as_str()).collect();

    // Validate services
    for (idx, service) in self.services.iter().enumerate() {
      let location = format!("services[{}]", idx);
      self.validate_service(service, &location, collector);
    }

    // Validate servers
    for (server_idx, server) in self.servers.iter().enumerate() {
      let server_location = format!("servers[{}]", server_idx);

      // Validate hostnames
      for (idx, hostname) in server.hostnames.iter().enumerate() {
        let hostname_location =
          format!("{}.hostnames[{}]", server_location, idx);
        self.validate_hostname(hostname, &hostname_location, collector);
      }

      // Validate users if present
      if let Some(ref users) = server.users {
        self.validate_users(
          users,
          &format!("{}.users", server_location),
          collector,
        );
      }

      // Validate TLS if present
      if let Some(ref tls) = server.tls {
        self.validate_server_tls(
          tls,
          &format!("{}.tls", server_location),
          collector,
        );
      }

      // Validate service reference
      if !server.service.is_empty()
        && !service_names.contains(server.service.as_str())
      {
        collector.add(
          format!("{}.service", server_location),
          format!("service '{}' not found", server.service),
          ConfigErrorKind::NotFound,
        );
      }

      // Validate listeners
      for (listener_idx, listener) in
        server.listeners.iter().enumerate()
      {
        let listener_location =
          format!("{}.listeners[{}]", server_location, listener_idx);
        self.validate_listener(
          listener,
          &listener_location,
          server.tls.as_ref(),
          server.users.as_ref(),
          collector,
        );
      }
    }

    // Validate SOCKS5 + hostnames semantic
    for (server_idx, server) in self.servers.iter().enumerate() {
      if !server.hostnames.is_empty() {
        // Check if any listener is SOCKS5 (report error once per server)
        let has_socks5 =
          server.listeners.iter().any(|l| l.kind == "socks5");
        if has_socks5 {
          collector.add(
            format!("servers[{}]", server_idx),
            "hostnames cannot be configured with SOCKS5 listener (SOCKS5 does not support hostname routing)".to_string(),
            ConfigErrorKind::InvalidFormat,
          );
        }
      }
    }

    // Validate address conflicts across all servers
    self.validate_address_conflicts(collector);
  }

  /// Validate address conflicts across all servers and listeners.
  ///
  /// Rules:
  /// - Different transport layer (TCP vs UDP): NO CONFLICT
  /// - Same transport layer, different kind: CONFLICT
  /// - Same kind, supports hostname routing: ALLOWED (Task 020 handles routing)
  /// - Same kind, NO hostname routing support (socks5): CONFLICT
  /// - Multiple default servers (empty hostnames) on same address+kind: CONFLICT (CR-003)
  fn validate_address_conflicts(
    &self,
    collector: &mut ConfigErrorCollector,
  ) {
    let mut address_map: HashMap<SocketAddr, Vec<AddressUsage>> =
      HashMap::new();

    for server in &self.servers {
      for listener in &server.listeners {
        let category = match ListenerCategory::from_kind(&listener.kind)
        {
          Some(c) => c,
          None => continue, // Unknown kind - already validated elsewhere
        };

        // Get addresses from listener args
        let addresses = self.extract_addresses(&listener.args);

        for addr_str in addresses {
          if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            let usage = AddressUsage {
              server_name: server.name.clone(),
              listener_kind: listener.kind.clone(),
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
          self.check_hostname_routing_conflicts(
            &tcp_usages,
            addr,
            collector,
          );
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
          self.check_hostname_routing_conflicts(
            &udp_usages,
            addr,
            collector,
          );
        }
      }
    }
  }

  /// Check for hostname routing conflicts sharing the same address+kind.
  ///
  /// CR-003: Multiple default servers on same (address, kind) causes routing ambiguity.
  /// Also detects exact hostname duplicates (case-insensitive, DNS rules).
  fn check_hostname_routing_conflicts(
    &self,
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

  /// Extract addresses from listener args.
  fn extract_addresses(&self, args: &SerializedArgs) -> Vec<String> {
    let mut addresses = Vec::new();

    // Try 'addresses' (plural) field first
    if let Some(addrs) = args.get("addresses") {
      if let Some(addr_list) = addrs.as_sequence() {
        for addr in addr_list {
          if let Some(addr_str) = addr.as_str() {
            addresses.push(addr_str.to_string());
          }
        }
      }
    }

    // Try 'address' (singular) field for backward compatibility
    if addresses.is_empty() {
      if let Some(addr) = args.get("address") {
        if let Some(addr_str) = addr.as_str() {
          addresses.push(addr_str.to_string());
        }
      }
    }

    addresses
  }

  /// Validate a single service configuration
  fn validate_service(
    &self,
    service: &Service,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    let kind_location = format!("{}.kind", location);
    let args_location = format!("{}.args", location);

    // Validate kind format
    let (plugin_name, service_name) =
      match parse_kind(&service.kind, &kind_location) {
        Ok(parts) => parts,
        Err(e) => {
          collector.add(e.location, e.message, e.kind);
          return;
        }
      };

    // Check plugin existence
    let Some(plugin_builder) =
      PluginBuilderSet::global().plugin_builder(plugin_name)
    else {
      collector.add(
        kind_location,
        format!("plugin '{}' not found", plugin_name),
        ConfigErrorKind::NotFound,
      );
      return;
    };

    // Create plugin instance and check service builder
    let plugin = plugin_builder();
    let Some(builder) = plugin.service_builder(service_name) else {
      collector.add(
        kind_location,
        format!(
          "service builder '{}' not found in plugin '{}'",
          service_name, plugin_name
        ),
        ConfigErrorKind::NotFound,
      );
      return;
    };

    // Validate args by calling the builder
    // This will catch args parsing errors
    if let Err(e) = builder(service.args.clone()) {
      collector.add(
        args_location,
        e.to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }
  }

  /// Validate a single listener configuration
  fn validate_listener(
    &self,
    listener: &Listener,
    location: &str,
    server_tls: Option<&ServerTlsConfig>,
    server_users: Option<&Vec<UserConfig>>,
    collector: &mut ConfigErrorCollector,
  ) {
    let kind_location = format!("{}.kind", location);
    let args_location = format!("{}.args", location);

    // Validate kind format
    let (_plugin_name, _listener_name) =
      match parse_kind(&listener.kind, &kind_location) {
        Ok(parts) => parts,
        Err(e) => {
          collector.add(e.location, e.message, e.kind);
          return;
        }
      };

    // Check listener builder existence directly using the full kind
    let Some(builder) =
      ListenerBuilderSet::global().listener_builder(&listener.kind)
    else {
      collector.add(
        kind_location,
        format!("listener builder '{}' not found", listener.kind),
        ConfigErrorKind::NotFound,
      );
      return;
    };

    // Validate args by calling the builder with a dummy service
    // This will catch args parsing errors
    // Pass server-level TLS and users config for listeners that need them
    // Create a minimal routing entry for validation
    let dummy_entry = crate::server::ServerRoutingEntry {
      hostnames: vec![],
      service: crate::server::placeholder_service(),
      service_name: String::new(),
      users: server_users.cloned(),
      tls: server_tls.cloned(),
      access_log_writer: None,
    };
    if let Err(e) = builder(
      listener.args.clone(),
      vec![dummy_entry],
    ) {
      collector.add(
        args_location,
        e.to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }

    // Validate addresses in listener args if present
    self.validate_listener_addresses(
      &listener.args,
      location,
      collector,
    );

    // Validate HTTP/3 listener specific configuration
    if listener.kind == "http3" {
      self.validate_http3_listener_args(
        &listener.args,
        location,
        collector,
      );
    }
  }

  /// Validate addresses in listener args
  fn validate_listener_addresses(
    &self,
    args: &SerializedArgs,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Check if args has an "addresses" field
    if let Some(addresses) = args.get("addresses")
      && let Some(addrs) = addresses.as_sequence()
    {
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
  fn validate_hostname(
    &self,
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

    // Check for wildcard
    if hostname.starts_with("*.") {
      let suffix = &hostname[2..];
      if suffix.is_empty() || !suffix.contains('.') {
        collector.add(
          location.to_string(),
          format!("invalid wildcard hostname '{}'", hostname),
          ConfigErrorKind::InvalidFormat,
        );
      }
    }
  }

  /// Validate server-level users configuration
  fn validate_users(
    &self,
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

  /// Validate server-level TLS configuration
  fn validate_server_tls(
    &self,
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
            && !content
              .contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
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

  /// Validate HTTP/3 listener specific configuration
  ///
  /// Validates:
  /// - Address format
  /// - QUIC parameters validity
  ///
  /// Note: TLS and auth are now at server level, not listener level.
  fn validate_http3_listener_args(
    &self,
    args: &SerializedArgs,
    location: &str,
    collector: &mut ConfigErrorCollector,
  ) {
    // Validate address format
    if let Some(address) = args.get("address")
      && let Some(addr_str) = address.as_str()
      && addr_str.parse::<std::net::SocketAddr>().is_err()
    {
      collector.add(
        format!("{}.args.address", location),
        format!("invalid address '{}'", addr_str),
        ConfigErrorKind::InvalidAddress,
      );
    }

    // Validate addresses (plural) field
    if let Some(addresses) = args.get("addresses")
      && let Some(addrs) = addresses.as_sequence()
    {
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

    // Validate QUIC parameters
    if let Some(quic) = args.get("quic") {
      self.validate_quic_config(
        quic,
        &format!("{}.args.quic", location),
        collector,
      );
    }

    // Note: TLS and auth are no longer validated at listener level.
    // They are now at server level and validated in validate_server_tls and validate_users.
  }

  /// Validate QUIC configuration parameters
  ///
  /// Validates QUIC parameters and reports errors for invalid values.
  /// Invalid parameters will cause startup to fail.
  fn validate_quic_config(
    &self,
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

  /// Load and validate configuration from a file
  ///
  /// Returns the config if valid, otherwise prints errors and exits.
  pub fn load_and_validate(path: &str) -> Config {
    let mut collector = ConfigErrorCollector::new();

    // Try to read and parse the file
    let mut config: Config = Default::default();
    match config.parse_file(path) {
      Ok(()) => {}
      Err(e) => {
        // Check if it's a file read error
        let err_str = e.to_string();
        if err_str.contains("read config file") {
          // File read error - print friendly message and exit
          eprintln!(
            "Error: Cannot read config file '{}': {}",
            path,
            err_str
              .replace(&format!("read config file '{}': ", path), "")
          );
          std::process::exit(1);
        } else {
          // YAML parse error
          collector.add("config", err_str, ConfigErrorKind::YamlParse);
          collector.report_and_exit();
        }
      }
    }

    // Validate the parsed config
    config.validate(&mut collector);

    // If there are validation errors, report and exit
    if collector.has_errors() {
      collector.report_and_exit();
    }

    config
  }

  pub fn global() -> &'static LazyLock<Config> {
    static CONFIG: LazyLock<Config> = LazyLock::new(|| {
      Config::load_and_validate(&CmdOpt::global().config_file)
    });
    &CONFIG
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Get the temporary directory for tests.
  /// Per constraint, we must use "tmp/" in the current directory instead of /tmp.
  /// This function also ensures the directory exists.
  fn get_temp_dir() -> std::path::PathBuf {
    let temp_dir = std::path::PathBuf::from("tmp");
    // Create the directory if it doesn't exist
    std::fs::create_dir_all(&temp_dir)
      .expect("Failed to create tmp directory");
    temp_dir
  }

  #[test]
  fn test_config_default() {
    let config = Config::default();
    assert_eq!(config.worker_threads, 1);
    assert_eq!(config.log_directory, "logs/");
    assert!(config.services.is_empty());
    assert!(config.servers.is_empty());
  }

  #[test]
  fn test_dummy_service_poll_ready() {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use tower::Service;

    // Create a no-op waker
    fn no_op_clone(_: *const ()) -> RawWaker {
      no_op_raw_waker()
    }
    fn no_op(_: *const ()) {}
    fn no_op_raw_waker() -> RawWaker {
      static VTABLE: RawWakerVTable =
        RawWakerVTable::new(no_op_clone, no_op, no_op, no_op);
      RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(no_op_raw_waker()) };
    let mut cx = Context::from_waker(&waker);

    let mut service = crate::server::placeholder_service();
    match service.poll_ready(&mut cx) {
      Poll::Ready(Ok(())) => {}
      _ => panic!("Expected Poll::Ready(Ok(()))"),
    }
  }

  #[test]
  fn test_dummy_service_call() {
    use http_body_util::BodyExt;
    use http_body_util::combinators::UnsyncBoxBody;
    use tower::Service;

    let mut service = crate::server::placeholder_service();
    let body: UnsyncBoxBody<bytes::Bytes, anyhow::Error> =
      http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
        .boxed_unsync();
    let request = http::Request::builder()
      .method("GET")
      .uri("/")
      .body(body)
      .unwrap();

    let future = service.call(request);
    // The future should complete with an error
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(future);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("placeholder"));
  }

  #[test]
  fn test_parse_string_valid() {
    let yaml = r#"
worker_threads: 2
log_directory: "test_logs/"
services: []
servers: []
"#;
    let mut config = Config::default();
    assert!(config.parse_string(yaml).is_ok());
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.log_directory, "test_logs/");
  }

  #[test]
  fn test_parse_string_invalid_yaml() {
    let yaml = r#"
worker_threads: [
  invalid
"#;
    let mut config = Config::default();
    assert!(config.parse_string(yaml).is_err());
  }

  #[test]
  fn test_validate_empty_config() {
    let config = Config::default();
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_valid_service() {
    let config = Config {
      services: vec![Service {
        name: "test_echo".to_string(),
        kind: "echo.echo".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_kind_format() {
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "invalidkind".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
  }

  #[test]
  fn test_validate_nonexistent_plugin() {
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "nonexistent.service".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(errors[0].message.contains("plugin"));
  }

  #[test]
  fn test_validate_nonexistent_service_builder() {
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "echo.nonexistent".to_string(),
        args: serde_yaml::Value::Null,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(errors[0].message.contains("service builder"));
  }

  #[test]
  fn test_validate_valid_listener() {
    let args =
      serde_yaml::from_str(r#"{addresses: ["127.0.0.1:8080"]}"#)
        .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_listener_kind() {
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          kind: "invalid".to_string(),
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
  }

  #[test]
  fn test_validate_nonexistent_listener_builder() {
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          kind: "hyper.nonexistent".to_string(),
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(
      errors[0]
        .message
        .contains("listener builder 'hyper.nonexistent' not found")
    );
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
    config.validate(&mut collector);
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
        kind: "echo.echo".to_string(),
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
    config.validate(&mut collector);
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
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidAddress);
    assert_eq!(errors[1].kind, ConfigErrorKind::InvalidAddress);
  }

  #[test]
  fn test_validate_addresses_non_string() {
    // Non-string items in addresses array cause args parsing error
    // because listener args expect Vec<String>
    let args =
      serde_yaml::from_str(r#"{addresses: [123, 456]}"#).unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // This is now an args parsing error
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
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
          kind: "echo.echo".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
        Service {
          name: "connect".to_string(),
          kind: "connect_tcp.connect_tcp".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
      ],
      servers: vec![
        Server {
          name: "server1".to_string(),
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: listener_args1,
          }],
          service: "echo".to_string(),
          ..Default::default()
        },
        Server {
          name: "server2".to_string(),
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: listener_args2,
          }],
          service: "connect".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_multiple_errors() {
    let config = Config {
      services: vec![
        Service {
          name: "test".to_string(),
          kind: "invalid.kind".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
        Service {
          name: "test2".to_string(),
          kind: "echo.nonexistent".to_string(),
          args: serde_yaml::Value::Null,
          layers: vec![],
        },
      ],
      servers: vec![Server {
        name: "server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 3);
  }

  #[test]
  fn test_cmd_opt_default_config_file() {
    let opt = CmdOpt {
      config_file: "conf/server.yaml".to_string(),
      version: false,
    };
    assert_eq!(opt.config_file, "conf/server.yaml");
  }

  #[test]
  fn test_service_default() {
    let service = Service::default();
    assert!(service.name.is_empty());
    assert!(service.kind.is_empty());
    assert!(service.layers.is_empty());
  }

  #[test]
  fn test_listener_default() {
    let listener = Listener::default();
    assert!(listener.kind.is_empty());
  }

  #[test]
  fn test_server_default() {
    let server = Server::default();
    assert!(server.name.is_empty());
    assert!(server.service.is_empty());
    assert!(server.listeners.is_empty());
  }

  #[test]
  fn test_layer_default() {
    let layer = Layer::default();
    assert!(layer.kind.is_empty());
  }

  #[test]
  fn test_config_clone() {
    let config = Config {
      worker_threads: 2,
      log_directory: "test/".to_string(),
      access_log: None,
      services: vec![],
      servers: vec![],
    };
    let cloned = config.clone();
    assert_eq!(cloned.worker_threads, 2);
  }

  #[test]
  fn test_validate_listener_plugin_not_found() {
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "nonexistent.listener".to_string(),
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert!(
      errors[0]
        .message
        .contains("listener builder 'nonexistent.listener' not found")
    );
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
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_addresses_missing_field() {
    // Missing required field 'addresses' causes args parsing error
    let args =
      serde_yaml::from_str(r#"{other_field: "value"}"#).unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // This is now an args parsing error (missing required field)
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(errors[0].message.contains("addresses"));
  }

  #[test]
  fn test_validate_addresses_empty_array() {
    let args = serde_yaml::from_str(r#"{addresses: []}"#).unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // Empty addresses is allowed at parse time (validation happens at runtime)
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_service_args_parsing_error() {
    // connect_tcp.connect_tcp expects () as args, not a map
    let args = serde_yaml::from_str(r#"{invalid: "field"}"#).unwrap();
    let config = Config {
      services: vec![Service {
        name: "test".to_string(),
        kind: "connect_tcp.connect_tcp".to_string(),
        args,
        layers: vec![],
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(errors[0].location.contains("args"));
  }

  #[test]
  fn test_validate_listener_args_parsing_error() {
    // Missing required field 'addresses' for http listener
    let args = serde_yaml::from_str(r#"{}"#).unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::InvalidFormat);
    assert!(errors[0].message.contains("addresses"));
  }

  #[test]
  fn test_load_and_validate_file_not_found() {
    // Create a temp file to ensure we have a unique non-existent path
    let temp_dir = get_temp_dir();
    let non_existent_path =
      temp_dir.join("neoproxy_test_nonexistent_config_12345.yaml");
    // Remove if it somehow exists
    let _ = std::fs::remove_file(&non_existent_path);

    // This test cannot use load_and_validate directly because it exits
    // Instead, we test parse_file with a non-existent path
    let mut config = Config::default();
    let result = config.parse_file(non_existent_path.to_str().unwrap());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("read config file"));
  }

  #[test]
  fn test_load_and_validate_valid_config() {
    // Create a temporary valid config file
    let temp_dir = get_temp_dir();
    let temp_path = temp_dir.join("neoproxy_test_valid_config.yaml");
    let config_content = r#"
worker_threads: 2
log_directory: "logs/"
services:
  - name: "echo_svc"
    kind: "echo.echo"
    args: null
    layers: []
servers:
  - name: "server1"
    listeners:
      - kind: "http"
        args:
          addresses: ["127.0.0.1:8080"]
    service: "echo_svc"
"#;
    std::fs::write(&temp_path, config_content).unwrap();

    let config = Config::load_and_validate(temp_path.to_str().unwrap());
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.servers.len(), 1);

    // Cleanup
    let _ = std::fs::remove_file(&temp_path);
  }

  #[test]
  fn test_parse_string_yaml_error() {
    let invalid_yaml = r#"
worker_threads: [
  invalid yaml
"#;
    let mut config = Config::default();
    let result = config.parse_string(invalid_yaml);
    assert!(result.is_err());
  }

  #[test]
  fn test_cmd_opt_global() {
    // CmdOpt::global() returns a static reference
    // We can't easily test the actual parsing without affecting global state
    // But we can verify the function exists and returns something
    let _opt = CmdOpt::global();
  }

  // =========================================================================
  // Access Log Config Tests
  // =========================================================================

  #[test]
  fn test_config_with_access_log() {
    let yaml = r#"
worker_threads: 1
log_directory: logs/
access_log:
  enabled: true
  path_prefix: "access.log"
  format: text
  buffer: 32kb
  flush: 1s
  max_size: 200mb
services: []
servers: []
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert!(config.access_log.is_some());
    let al = config.access_log.as_ref().unwrap();
    assert!(al.enabled);
    assert_eq!(al.path_prefix, "access.log");
  }

  #[test]
  fn test_config_without_access_log() {
    let yaml = r#"
worker_threads: 1
log_directory: logs/
services: []
servers: []
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert!(config.access_log.is_none());
  }

  #[test]
  fn test_server_with_access_log_override() {
    let yaml = r#"
worker_threads: 1
log_directory: logs/
access_log:
  enabled: true
  format: text
servers:
  - name: http_proxy
    service: tunnel
    access_log:
      path_prefix: "http_access.log"
      format: json
    listeners: []
services:
  - name: tunnel
    kind: connect_tcp.connect_tcp
"#;
    let mut config = Config::default();
    config.parse_string(yaml).unwrap();
    assert!(config.access_log.is_some());
    assert!(config.servers[0].access_log.is_some());
    let server_al = config.servers[0].access_log.as_ref().unwrap();
    assert_eq!(
      server_al.path_prefix,
      Some("http_access.log".to_string())
    );
    // format is explicitly set
    assert!(matches!(
      server_al.format,
      Some(crate::access_log::LogFormat::Json)
    ));
    // buffer is NOT set, should be None (inherited from top-level at merge time)
    assert!(server_al.buffer.is_none());
  }

  // =========================================================================
  // TLS Configuration Tests
  // =========================================================================

  #[test]
  fn test_certificate_config_deserialize() {
    let yaml = r#"
cert_path: "/path/to/cert.pem"
key_path: "/path/to/key.pem"
"#;
    let cert: CertificateConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cert.cert_path, "/path/to/cert.pem");
    assert_eq!(cert.key_path, "/path/to/key.pem");
  }

  #[test]
  fn test_server_tls_config_deserialize_single_cert() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 1);
    assert_eq!(tls.certificates[0].cert_path, "/path/to/cert.pem");
    assert_eq!(tls.certificates[0].key_path, "/path/to/key.pem");
    assert!(tls.client_ca_certs.is_none());
  }

  #[test]
  fn test_server_tls_config_deserialize_multiple_certs() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert1.pem"
    key_path: "/path/to/key1.pem"
  - cert_path: "/path/to/cert2.pem"
    key_path: "/path/to/key2.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 2);
  }

  #[test]
  fn test_server_tls_config_deserialize_with_client_ca() {
    let yaml = r#"
certificates:
  - cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
client_ca_certs:
  - "/path/to/ca1.pem"
  - "/path/to/ca2.pem"
"#;
    let tls: ServerTlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(tls.certificates.len(), 1);
    assert!(tls.client_ca_certs.is_some());
    let client_cas = tls.client_ca_certs.unwrap();
    assert_eq!(client_cas.len(), 2);
    assert_eq!(client_cas[0], "/path/to/ca1.pem");
    assert_eq!(client_cas[1], "/path/to/ca2.pem");
  }

  #[test]
  fn test_server_tls_config_missing_certificates() {
    let yaml = r#"{}"#;
    let result: Result<ServerTlsConfig, _> = serde_yaml::from_str(yaml);
    // certificates field is required
    assert!(result.is_err());
  }

  #[test]
  fn test_certificate_config_missing_fields() {
    // Missing cert_path
    let yaml = r#"key_path: "/path/to/key.pem""#;
    let result: Result<CertificateConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err());

    // Missing key_path
    let yaml = r#"cert_path: "/path/to/cert.pem""#;
    let result: Result<CertificateConfig, _> =
      serde_yaml::from_str(yaml);
    assert!(result.is_err());
  }

  // =========================================================================
  // SOCKS5 Hostname Validation Tests
  // =========================================================================

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
        listeners: vec![Listener { kind: "socks5".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
        listeners: vec![Listener { kind: "socks5".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
        listeners: vec![Listener { kind: "http".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
        listeners: vec![Listener { kind: "socks5".to_string(), args }],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
          Listener { kind: "socks5".to_string(), args: args1 },
          Listener { kind: "socks5".to_string(), args: args2 },
          Listener { kind: "socks5".to_string(), args: args3 },
        ],
        service: "".to_string(),
        ..Default::default()
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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

  // =========================================================================
  // Hostname Duplicate Detection Tests (Task 002)
  // =========================================================================

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
            kind: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()], // Duplicate!
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args2,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
            kind: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["api.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args2,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
            kind: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["*.example.com".to_string()], // Duplicate wildcard!
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args2,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
            kind: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "specific".to_string(),
          hostnames: vec!["api.example.com".to_string()], // Exact match, OK
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args2,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
            kind: "http".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "server_b".to_string(),
          hostnames: vec!["web.example.com".to_string()],
          listeners: vec![Listener {
            kind: "http".to_string(),
            args: args2,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    // Should NOT have hostname conflict errors
    let errors = collector.errors();
    let found = errors
      .iter()
      .any(|e| e.message.contains("defined in multiple servers"));
    assert!(!found, "Different hostnames should not be a conflict");
  }

  // =========================================================================
  // SOCKS5 Conflict via Default Server Check Tests (Task 003)
  // =========================================================================

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
            kind: "socks5".to_string(),
            args: args1,
          }],
          service: "".to_string(),
          ..Default::default()
        },
        Server {
          name: "socks_b".to_string(),
          hostnames: vec![], // SOCKS5 has no hostnames
          listeners: vec![Listener {
            kind: "socks5".to_string(),
            args: args2,
          }],
          service: "".to_string(),
          ..Default::default()
        },
      ],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
}
