//! Black-box tests for the config module.

use crate::config::{Config, ListenerConfig, Server};

/// Get the temporary directory for tests.
fn get_temp_dir() -> std::path::PathBuf {
  let temp_dir = std::path::PathBuf::from("tmp");
  std::fs::create_dir_all(&temp_dir)
    .expect("Failed to create tmp directory");
  temp_dir
}

#[test]
fn test_default_empty_config() {
  let config = Config::default();
  assert_eq!(config.server_threads(), 4);
  assert!(config.listeners().is_empty());
  assert!(config.services().is_empty());
  assert!(config.servers().is_empty());
  assert!(config.plugins().is_empty());
  assert!(config.tls_provider().is_none());
}

#[test]
fn test_parse_str_valid_config() {
  let yaml = r#"
server_threads: 2
services: []
servers: []
"#;

  let config = Config::parse_str(yaml).unwrap();

  assert_eq!(config.server_threads(), 2);
  assert!(config.listeners().is_empty());
  assert!(config.services().is_empty());
  assert!(config.servers().is_empty());
}

#[test]
fn test_parse_str_invalid_yaml() {
  let yaml = r#"
server_threads: [
  invalid
"#;

  assert!(Config::parse_str(yaml).is_err());
}

#[test]
fn test_listener_config_default() {
  let listener = ListenerConfig::default();

  assert!(listener.name().is_empty());
  assert!(listener.kind().is_empty());
  assert!(listener.addresses().is_empty());
}

#[test]
fn test_listener_config_deserialize() {
  let yaml = r#"
name: http_main
kind: http
addresses:
  - "0.0.0.0:8080"
"#;

  let listener: ListenerConfig = serde_yaml::from_str(yaml).unwrap();

  assert_eq!(listener.name(), "http_main");
  assert_eq!(listener.kind(), "http");
  assert_eq!(listener.addresses(), ["0.0.0.0:8080"]);
}

#[test]
fn test_parse_str_listener_references_are_names() {
  let yaml = r#"
listeners:
  - name: http_main
    kind: http
    addresses: ["127.0.0.1:8080"]
services: []
servers:
  - name: server1
    listeners:
      - http_main
    service: ""
"#;

  let config = Config::parse_str(yaml).unwrap();

  assert_eq!(config.servers()[0].listeners(), ["http_main"]);
  assert_eq!(config.listeners()[0].kind(), "http");
  assert_eq!(config.listeners()[0].addresses(), ["127.0.0.1:8080"]);
}

#[test]
fn test_server_default() {
  let server = Server::default();

  assert!(server.name().is_empty());
  assert!(server.service().is_empty());
  assert!(server.listeners().is_empty());
  assert!(server.hostnames().is_empty());
  assert!(server.tls().is_none());
}

#[test]
fn test_config_clone() {
  let config = Config::parse_str(
    r#"
server_threads: 2
services: []
servers: []
"#,
  )
  .unwrap();

  let cloned = config.clone();

  assert_eq!(cloned.server_threads(), 2);
  assert!(cloned.services().is_empty());
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

  assert_eq!(config.server_threads(), 2);
  assert_eq!(config.services().len(), 1);
  assert_eq!(config.servers().len(), 1);

  let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_parse_str_service_kind_split_into_parts() {
  let yaml = r#"
services:
  - name: echo_svc
    kind: "echo.echo"
    args: null
    layers: []
servers: []
"#;

  let config = Config::parse_str(yaml).unwrap();

  assert_eq!(config.services()[0].plugin_name(), "echo");
  assert_eq!(config.services()[0].kind(), "echo");
}

#[test]
fn test_parse_str_layer_kind_split_into_parts() {
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

  let config = Config::parse_str(yaml).unwrap();

  assert_eq!(config.services()[0].layers()[0].plugin_name(), "echo");
  assert_eq!(config.services()[0].layers()[0].kind(), "echo");
}

#[test]
fn test_parse_str_service_kind_missing_dot() {
  let yaml = r#"
services:
  - name: test
    kind: "invalidkind"
    args: null
    layers: []
servers: []
"#;

  let result = Config::parse_str(yaml);

  assert!(result.is_err(), "missing dot should be rejected");
  let err_msg = format!("{}", result.unwrap_err());
  assert!(
    err_msg.contains("invalid service kind"),
    "error should mention invalid service kind, got: {}",
    err_msg
  );
}

#[test]
fn test_parse_str_service_kind_empty_service_name() {
  let yaml = r#"
services:
  - name: test
    kind: "echo."
    args: null
    layers: []
servers: []
"#;

  let result = Config::parse_str(yaml);

  assert!(
    result.is_err(),
    "empty service name after dot should be rejected"
  );
}

#[test]
fn test_parse_str_service_kind_empty_plugin_name() {
  let yaml = r#"
services:
  - name: test
    kind: ".echo"
    args: null
    layers: []
servers: []
"#;

  let result = Config::parse_str(yaml);

  assert!(
    result.is_err(),
    "empty plugin name before dot should be rejected"
  );
}

#[test]
fn test_parse_str_service_kind_empty_string() {
  let yaml = r#"
services:
  - name: test
    kind: ""
    args: null
    layers: []
servers: []
"#;

  let result = Config::parse_str(yaml);

  assert!(result.is_err(), "empty kind string should be rejected");
}

#[test]
fn test_parse_str_service_kind_multiple_dots() {
  let yaml = r#"
services:
  - name: test
    kind: "echo.echo.echo"
    args: null
    layers: []
servers: []
"#;

  let result = Config::parse_str(yaml);

  assert!(result.is_err(), "multiple dots should be rejected");
}

#[test]
fn test_parse_str_layer_kind_missing_dot() {
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

  let result = Config::parse_str(yaml);

  assert!(result.is_err(), "layer with missing dot should be rejected");
}

#[test]
fn test_parse_str_layer_kind_empty_parts() {
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

  let result = Config::parse_str(yaml);

  assert!(
    result.is_err(),
    "layer with empty service name should be rejected"
  );
}

#[test]
fn test_parse_str_plugins_default_empty() {
  let config = Config::parse_str(
    r#"
services: []
servers: []
"#,
  )
  .unwrap();

  assert!(config.plugins().is_empty());
}

#[test]
fn test_parse_str_plugins_preserved() {
  let yaml = r#"
plugins:
  access_log:
    writers:
      - path_prefix: "logs/audit"
services: []
servers: []
"#;

  let config = Config::parse_str(yaml).unwrap();

  assert!(config.plugins().contains_key("access_log"));
  let access_log_config = &config.plugins()["access_log"];
  let mapping = access_log_config.as_mapping().unwrap();
  assert!(
    mapping
      .contains_key(serde_yaml::Value::String("writers".to_string()))
  );
}
