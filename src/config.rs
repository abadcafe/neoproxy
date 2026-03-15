use std::collections::HashSet;
use std::fs;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

use crate::config_validator::{
  ConfigErrorCollector, ConfigErrorKind, parse_kind,
};
use crate::plugin;
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
  pub args: serde_yaml::Value,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Server {
  pub name: String,
  pub listeners: Vec<Listener>,
  pub service: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Layer {
  pub kind: String,
  // delegate the deserializition to layer factories
  pub args: serde_yaml::Value,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Service {
  pub name: String,
  pub kind: String,
  // delegate the deserializition to service factories.
  pub args: serde_yaml::Value,
  pub layers: Vec<Layer>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
  pub worker_threads: usize,
  pub log_directory: String,
  pub services: Vec<Service>,
  pub servers: Vec<Server>,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      worker_threads: 1,
      log_directory: String::from("logs/"),
      services: vec![],
      servers: vec![],
    }
  }
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
        self.validate_listener(listener, &listener_location, collector);
      }
    }
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
    collector: &mut ConfigErrorCollector,
  ) {
    let kind_location = format!("{}.kind", location);
    let args_location = format!("{}.args", location);

    // Validate kind format
    let (plugin_name, listener_name) =
      match parse_kind(&listener.kind, &kind_location) {
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

    // Create plugin instance and check listener builder
    let plugin = plugin_builder();
    let Some(builder) = plugin.listener_builder(listener_name) else {
      collector.add(
        kind_location,
        format!(
          "listener builder '{}' not found in plugin '{}'",
          listener_name, plugin_name
        ),
        ConfigErrorKind::NotFound,
      );
      return;
    };

    // Validate args by calling the builder with a dummy service
    // This will catch args parsing errors
    let dummy_service = plugin::Service::new(DummyService {});
    if let Err(e) = builder(listener.args.clone(), dummy_service) {
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
  }

  /// Validate addresses in listener args
  fn validate_listener_addresses(
    &self,
    args: &serde_yaml::Value,
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

/// A dummy service used for validating listener args
/// This service does nothing and is only used to pass to
/// listener builders during validation
#[derive(Clone)]
struct DummyService {}

impl tower::Service<plugin::Request> for DummyService {
  type Error = anyhow::Error;
  type Future = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<plugin::Response>>>,
  >;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    _cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<()>> {
    std::task::Poll::Ready(Ok(()))
  }

  fn call(&mut self, _req: plugin::Request) -> Self::Future {
    Box::pin(async {
      anyhow::bail!("DummyService should not be called")
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_config_default() {
    let config = Config::default();
    assert_eq!(config.worker_threads, 1);
    assert_eq!(config.log_directory, "logs/");
    assert!(config.services.is_empty());
    assert!(config.servers.is_empty());
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
    let args = serde_yaml::from_str(
      r#"{addresses: ["127.0.0.1:8080"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
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
  fn test_validate_nonexistent_listener_builder() {
    let config = Config {
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![Listener {
          kind: "hyper.nonexistent".to_string(),
          args: serde_yaml::Value::Null,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].kind, ConfigErrorKind::NotFound);
    assert!(errors[0].message.contains("listener builder"));
  }

  #[test]
  fn test_validate_service_reference_not_found() {
    let config = Config {
      services: vec![],
      servers: vec![Server {
        name: "test_server".to_string(),
        listeners: vec![],
        service: "nonexistent".to_string(),
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
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_valid_address() {
    let args = serde_yaml::from_str(
      r#"{addresses: ["127.0.0.1:8080"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_invalid_address() {
    let args = serde_yaml::from_str(
      r#"{addresses: ["invalid:address"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
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
      r#"{addresses: ["invalid1", "127.0.0.1:8080", "invalid2"], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
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
    // because HyperListenerArgs.addresses is Vec<String>
    let args = serde_yaml::from_str(
      r#"{addresses: [123, 456], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
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
    let listener_args: serde_yaml::Value = serde_yaml::from_str(
      r#"{addresses: ["127.0.0.1:8080"], protocols: [], hostnames: []}"#,
    )
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
            kind: "hyper.listener".to_string(),
            args: listener_args.clone(),
          }],
          service: "echo".to_string(),
        },
        Server {
          name: "server2".to_string(),
          listeners: vec![Listener {
            kind: "hyper.listener".to_string(),
            args: listener_args,
          }],
          service: "connect".to_string(),
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
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
    assert!(collector.has_errors());
    let errors = collector.errors();
    assert_eq!(errors.len(), 1);
    assert!(
      errors[0].message.contains("plugin 'nonexistent' not found")
    );
  }

  #[test]
  fn test_validate_empty_service_name() {
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![],
        service: "".to_string(), // empty service name should be allowed
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
    let args = serde_yaml::from_str(
      r#"{other_field: "value", protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
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
    let args = serde_yaml::from_str(
      r#"{addresses: [], protocols: [], hostnames: []}"#,
    )
    .unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
      }],
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    config.validate(&mut collector);
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
    // Missing required field 'addresses' for hyper.listener
    let args = serde_yaml::from_str(r#"{protocols: []}"#).unwrap();
    let config = Config {
      servers: vec![Server {
        name: "test".to_string(),
        listeners: vec![Listener {
          kind: "hyper.listener".to_string(),
          args,
        }],
        service: "".to_string(),
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
    let non_existent_path =
      "/tmp/neoproxy_test_nonexistent_config_12345.yaml";
    // Remove if it somehow exists
    let _ = std::fs::remove_file(non_existent_path);

    // This test cannot use load_and_validate directly because it exits
    // Instead, we test parse_file with a non-existent path
    let mut config = Config::default();
    let result = config.parse_file(non_existent_path);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("read config file"));
  }

  #[test]
  fn test_load_and_validate_valid_config() {
    // Create a temporary valid config file
    let temp_dir = std::env::temp_dir();
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
      - kind: "hyper.listener"
        args:
          addresses: ["127.0.0.1:8080"]
          protocols: []
          hostnames: []
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
}
