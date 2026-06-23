use super::service::*;
use super::{
  ConfigError, ConfigErrorCollector, Layer, LayerRaw, SerializedArgs,
};

#[test]
fn test_validate_service_not_found() {
  let service_names: std::collections::HashSet<&str> =
    std::collections::HashSet::new();
  let mut collector = ConfigErrorCollector::new();
  validate_service(&service_names, 0, "nonexistent", &mut collector);
  assert!(
    collector.has_errors(),
    "Nonexistent service reference should produce error"
  );
  let found = collector
    .errors()
    .iter()
    .any(|e| matches!(e, ConfigError::NotFound { .. }));
  assert!(found, "Should have NotFound error for missing service");
}

#[test]
fn test_validate_service_found() {
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
fn test_validate_service_empty_name() {
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

#[test]
fn test_layer_default() {
  let layer = Layer::default();
  assert!(layer.plugin_name.is_empty());
  assert!(layer.kind.is_empty());
}

#[test]
fn test_service_default() {
  let service = Service::default();
  assert!(service.name.is_empty());
  assert!(service.plugin_name.is_empty());
  assert!(service.kind.is_empty());
  assert!(service.layers.is_empty());
}

#[test]
fn test_layer_raw_parse() {
  let raw = LayerRaw {
    kind: "auth.basic_auth".to_string(),
    args: SerializedArgs::Null,
  };
  let layer = raw.parse().unwrap();
  assert_eq!(layer.plugin_name, "auth");
  assert_eq!(layer.kind, "basic_auth");
}

#[test]
fn test_layer_raw_parse_invalid() {
  let raw =
    LayerRaw { kind: "nodot".to_string(), args: SerializedArgs::Null };
  assert!(raw.parse().is_err());
}

#[test]
fn test_service_raw_parse() {
  let raw = ServiceRaw {
    name: "my_svc".to_string(),
    kind: "connect_tcp.connect_tcp".to_string(),
    args: SerializedArgs::Null,
    layers: vec![],
  };
  let svc = raw.parse().unwrap();
  assert_eq!(svc.plugin_name, "connect_tcp");
  assert_eq!(svc.kind, "connect_tcp");
  assert_eq!(svc.name, "my_svc");
  assert!(svc.layers.is_empty());
}

#[test]
fn test_service_raw_parse_invalid() {
  let raw = ServiceRaw {
    name: "my_svc".to_string(),
    kind: "nodot".to_string(),
    args: SerializedArgs::Null,
    layers: vec![],
  };
  assert!(raw.parse().is_err());
}

#[test]
fn test_service_raw_parse_with_layers() {
  let raw = ServiceRaw {
    name: "my_svc".to_string(),
    kind: "echo.echo".to_string(),
    args: SerializedArgs::Null,
    layers: vec![
      LayerRaw {
        kind: "auth.basic_auth".to_string(),
        args: SerializedArgs::Null,
      },
      LayerRaw {
        kind: "access_log.file".to_string(),
        args: SerializedArgs::Null,
      },
    ],
  };
  let svc = raw.parse().unwrap();
  assert_eq!(svc.layers.len(), 2);
  assert_eq!(svc.layers[0].plugin_name, "auth");
  assert_eq!(svc.layers[1].plugin_name, "access_log");
}
