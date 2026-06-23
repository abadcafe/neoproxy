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
