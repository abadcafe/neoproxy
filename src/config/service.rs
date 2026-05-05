//! Service and layer configuration types.

use serde::Deserialize;

use super::{
  ConfigError, ConfigErrorCollector, Layer, LayerRaw, SerializedArgs,
};

/// Service configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceRaw {
  pub name: String,
  pub kind: String,
  pub args: SerializedArgs,
  pub layers: Vec<LayerRaw>,
}

/// Service configuration (after kind parsing).
#[derive(Default, Clone, Debug)]
pub struct Service {
  pub name: String,
  pub plugin_name: String,
  pub kind: String,
  pub args: SerializedArgs,
  pub layers: Vec<Layer>,
}

/// Parse a `plugin_name.entity_name` kind string into (plugin_name,
/// entity_name).
///
/// Requires exactly one dot separator with non-empty parts on both
/// sides.
fn parse_plugin_kind(
  kind: &str,
  entity_name: &str,
) -> anyhow::Result<(String, String)> {
  if kind.is_empty() {
    return Err(anyhow::anyhow!(
      "invalid {} kind '', expected 'plugin_name.{}_name'",
      entity_name,
      entity_name
    ));
  }
  let dot_count = kind.matches('.').count();
  if dot_count != 1 {
    return Err(anyhow::anyhow!(
      "invalid {} kind '{}', expected 'plugin_name.{}_name'",
      entity_name,
      kind,
      entity_name
    ));
  }
  let parts: Vec<&str> = kind.splitn(2, '.').collect();
  let plugin_name = parts[0];
  let name = parts[1];
  if plugin_name.is_empty() || name.is_empty() {
    return Err(anyhow::anyhow!(
      "invalid {} kind '{}', expected 'plugin_name.{}_name'",
      entity_name,
      kind,
      entity_name
    ));
  }
  Ok((plugin_name.to_string(), name.to_string()))
}

impl LayerRaw {
  pub fn parse(self) -> anyhow::Result<Layer> {
    let (plugin_name, kind) = parse_plugin_kind(&self.kind, "layer")?;
    Ok(Layer { plugin_name, kind, args: self.args })
  }
}

impl ServiceRaw {
  pub fn parse(self) -> anyhow::Result<Service> {
    let (plugin_name, kind) = parse_plugin_kind(&self.kind, "service")?;
    let layers = self
      .layers
      .into_iter()
      .map(|lr| lr.parse())
      .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Service {
      name: self.name,
      plugin_name,
      kind,
      args: self.args,
      layers,
    })
  }
}

/// Validate a server's service reference.
///
/// Checks that the server's service field references an existing
/// service. Empty service names are allowed (for servers without a
/// service).
///
/// Note: This function validates the service *reference* from a server,
/// not the service configuration itself. Service configuration
/// validation (kind format, plugin existence) is handled at parse time
/// and runtime.
pub fn validate_service(
  service_names: &std::collections::HashSet<&str>,
  server_idx: usize,
  service: &str,
  collector: &mut ConfigErrorCollector,
) {
  if !service.is_empty() && !service_names.contains(service) {
    collector.add(ConfigError::NotFound {
      location: format!("servers[{}].service", server_idx),
      message: format!("service '{}' not found", service),
    });
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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
    let raw = LayerRaw {
      kind: "nodot".to_string(),
      args: SerializedArgs::Null,
    };
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
}
