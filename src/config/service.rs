//! Service and layer configuration types.

use serde::Deserialize;

use super::SerializedArgs;
use super::{ConfigErrorCollector, ConfigErrorKind};

/// Layer configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct LayerRaw {
  pub kind: String,
  pub args: SerializedArgs,
}

/// Layer configuration (after kind parsing).
#[derive(Default, Clone, Debug)]
pub struct Layer {
  pub plugin_name: String,
  pub layer_name: String,
  pub args: SerializedArgs,
}

/// Service configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
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
  pub service_name: String,
  pub args: SerializedArgs,
  pub layers: Vec<Layer>,
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
    let found = collector.errors().iter().any(|e| {
      e.kind == ConfigErrorKind::NotFound
        && e.message.contains("service 'nonexistent' not found")
    });
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
    assert!(layer.layer_name.is_empty());
  }

  #[test]
  fn test_service_default() {
    let service = Service::default();
    assert!(service.name.is_empty());
    assert!(service.plugin_name.is_empty());
    assert!(service.service_name.is_empty());
    assert!(service.layers.is_empty());
  }
}
