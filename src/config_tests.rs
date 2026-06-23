//! Black-box tests for the config module.

use std::collections::HashMap;

use crate::config::{
  CmdOpt, Config, ConfigRaw, ListenerConfig, Server,
};

/// Get the temporary directory for tests.
fn get_temp_dir() -> std::path::PathBuf {
  let temp_dir = std::path::PathBuf::from("tmp");
  std::fs::create_dir_all(&temp_dir)
    .expect("Failed to create tmp directory");
  temp_dir
}

#[test]
fn test_config_default() {
  let config = Config::default();
  assert_eq!(config.server_threads, 4);
  assert!(config.listeners.is_empty());
  assert!(config.services.is_empty());
  assert!(config.servers.is_empty());
  assert!(config.plugins.is_empty());
}

#[test]
fn test_parse_string_valid() {
  let yaml = r#"
server_threads: 2
services: []
servers: []
"#;
  let mut config = Config::default();
  assert!(config.parse_string(yaml).is_ok());
  assert_eq!(config.server_threads, 2);
}

#[test]
fn test_parse_string_invalid_yaml() {
  let yaml = r#"
server_threads: [
  invalid
"#;
  let mut config = Config::default();
  assert!(config.parse_string(yaml).is_err());
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
fn test_listener_config_default() {
  let lc = ListenerConfig::default();
  assert!(lc.name.is_empty());
  assert!(lc.kind.is_empty());
  assert!(lc.addresses.is_empty());
}

#[test]
fn test_listener_config_deserialize() {
  let yaml = r#"
name: http_main
kind: http
addresses:
  - "0.0.0.0:8080"
"#;
  let lc: ListenerConfig = serde_yaml::from_str(yaml).unwrap();
  assert_eq!(lc.name, "http_main");
  assert_eq!(lc.kind, "http");
  assert_eq!(lc.addresses, vec!["0.0.0.0:8080"]);
}

#[test]
fn test_listener_field_is_string_reference() {
  let yaml = r#"
listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:8080"]
servers:
  - name: server1
    listeners:
      - http_main
    service: ""
"#;
  let mut config = Config::default();
  config.parse_string(yaml).unwrap();
  assert_eq!(config.servers[0].listeners[0], "http_main");
  assert_eq!(config.listeners[0].kind, "http");
  assert_eq!(config.listeners[0].addresses, vec!["127.0.0.1:8080"]);
}

#[test]
fn test_server_default() {
  let server = Server::default();
  assert!(server.name.is_empty());
  assert!(server.service.is_empty());
  assert!(server.listeners.is_empty());
}

#[test]
fn test_config_clone() {
  let config = Config {
    server_threads: 2,
    listeners: vec![],
    services: vec![],
    servers: vec![],
    plugins: HashMap::new(),
    tls_provider: None,
  };
  let cloned = config.clone();
  assert_eq!(cloned.server_threads, 2);
}

#[test]
fn test_load_file_not_found() {
  let temp_dir = get_temp_dir();
  let non_existent_path =
    temp_dir.join("neoproxy_test_nonexistent_config_12345.yaml");
  let _ = std::fs::remove_file(&non_existent_path);

  let result = Config::load(non_existent_path.to_str().unwrap());
  assert!(result.is_err());
  let err = result.unwrap_err().to_string();
  assert!(err.contains("read config file"));
}

#[test]
fn test_load_valid_config() {
  let temp_dir = get_temp_dir();
  let temp_path = temp_dir.join("neoproxy_test_valid_config.yaml");
  let config_content = r#"
server_threads: 2
listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:8080"]
services:
  - name: "echo_svc"
    kind: "echo.echo"
    args: null
    layers: []
servers:
  - name: "server1"
    listeners:
      - "http_main"
    service: "echo_svc"
"#;
  std::fs::write(&temp_path, config_content).unwrap();

  let config = Config::load(temp_path.to_str().unwrap()).unwrap();
  assert_eq!(config.server_threads, 2);
  assert_eq!(config.services.len(), 1);
  assert_eq!(config.servers.len(), 1);

  let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_parse_string_yaml_error() {
  let invalid_yaml = r#"
server_threads: [
  invalid yaml
"#;
  let mut config = Config::default();
  let result = config.parse_string(invalid_yaml);
  assert!(result.is_err());
}

#[test]
fn test_cmd_opt_global() {
  let _opt = CmdOpt::global();
}

// =========================================================================
// Split Kind Fields Tests
// =========================================================================

#[test]
fn test_service_kind_split_into_parts() {
  let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers: []
servers: []
"#;
  let mut config = Config::default();
  config.parse_string(yaml).unwrap();
  assert_eq!(config.services[0].plugin_name, "echo");
  assert_eq!(config.services[0].kind, "echo");
}

#[test]
fn test_layer_kind_split_into_parts() {
  let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers:
      - kind: "echo.echo"
        args: null
servers: []
"#;
  let mut config = Config::default();
  config.parse_string(yaml).unwrap();
  assert_eq!(config.services[0].layers[0].plugin_name, "echo");
  assert_eq!(config.services[0].layers[0].kind, "echo");
}

#[test]
fn test_service_kind_missing_dot() {
  let yaml = r#"
services:
  - name: test
    kind: "invalidkind"
    args: null
    layers: []
servers: []
"#;
  let mut config = Config::default();
  let result = config.parse_string(yaml);
  assert!(result.is_err(), "Missing dot should be rejected");
  let err_msg = format!("{}", result.unwrap_err());
  assert!(
    err_msg.contains("invalid service kind"),
    "Error should mention 'invalid service kind', got: {}",
    err_msg
  );
}

#[test]
fn test_service_kind_empty_service_name() {
  let yaml = r#"
services:
  - name: test
    kind: "echo."
    args: null
    layers: []
servers: []
"#;
  let mut config = Config::default();
  let result = config.parse_string(yaml);
  assert!(
    result.is_err(),
    "Empty service name after dot should be rejected"
  );
}

#[test]
fn test_service_kind_empty_plugin_name() {
  let yaml = r#"
services:
  - name: test
    kind: ".echo"
    args: null
    layers: []
servers: []
"#;
  let mut config = Config::default();
  let result = config.parse_string(yaml);
  assert!(
    result.is_err(),
    "Empty plugin name before dot should be rejected"
  );
}

#[test]
fn test_service_kind_empty_string() {
  let yaml = r#"
services:
  - name: test
    kind: ""
    args: null
    layers: []
servers: []
"#;
  let mut config = Config::default();
  let result = config.parse_string(yaml);
  assert!(result.is_err(), "Empty kind string should be rejected");
}

#[test]
fn test_service_kind_multiple_dots() {
  let yaml = r#"
services:
  - name: test
    kind: "echo.echo.echo"
    args: null
    layers: []
servers: []
"#;
  let mut config = Config::default();
  let result = config.parse_string(yaml);
  assert!(result.is_err(), "Multiple dots should be rejected");
}

#[test]
fn test_layer_kind_missing_dot() {
  let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers:
      - kind: "invalidkind"
        args: null
servers: []
"#;
  let mut config = Config::default();
  let result = config.parse_string(yaml);
  assert!(result.is_err(), "Layer with missing dot should be rejected");
}

#[test]
fn test_layer_kind_empty_parts() {
  let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers:
      - kind: "echo."
        args: null
servers: []
"#;
  let mut config = Config::default();
  let result = config.parse_string(yaml);
  assert!(
    result.is_err(),
    "Layer with empty service name should be rejected"
  );
}

// =========================================================================
// ConfigRaw Deserialization Tests
// =========================================================================

#[test]
fn test_config_raw_deserialize() {
  let yaml = r#"
listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:8080"]
servers:
  - name: default
    hostnames: []
    listeners: ["http_main"]
    service: echo_svc
services:
  - name: echo_svc
    kind: echo.echo
"#;
  let raw: ConfigRaw = serde_yaml::from_str(yaml).unwrap();
  assert_eq!(raw.listeners.len(), 1);
  assert_eq!(raw.listeners[0].name, "http_main");
  assert_eq!(raw.servers[0].listeners, vec!["http_main"]);
  assert_eq!(raw.server_threads, 4); // default
}

#[test]
fn test_config_raw_plugins_default_empty() {
  let yaml = r#"
services: []
servers: []
"#;
  let raw: ConfigRaw = serde_yaml::from_str(yaml).unwrap();
  assert!(raw.plugins.is_empty());
}

#[test]
fn test_config_raw_plugins_parsed() {
  let yaml = r#"
plugins:
  access_log:
    writers:
      - path_prefix: "logs/audit"
services: []
servers: []
"#;
  let raw: ConfigRaw = serde_yaml::from_str(yaml).unwrap();
  assert!(raw.plugins.contains_key("access_log"));
  let access_log_config = &raw.plugins["access_log"];
  assert!(access_log_config.as_mapping().is_some());
  let mapping = access_log_config.as_mapping().unwrap();
  assert!(
    mapping
      .contains_key(&serde_yaml::Value::String("writers".to_string()))
  );
}

#[test]
fn test_config_raw_plugins_preserved_in_parse_string() {
  let yaml = r#"
plugins:
  access_log:
    writers:
      - path_prefix: "logs/audit"
services: []
servers: []
"#;
  let mut config = Config::default();
  config.parse_string(yaml).unwrap();
  assert!(config.plugins.contains_key("access_log"));
}
