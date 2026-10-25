//! module: service
//! responsibility: parse and expose configured services
//! public operations: Service accessors and Debug, ServiceRaw::parse,
//! validate_service
//! data entities: Service, ServiceRaw
//! tests: service_tests.rs; config_tests.rs via config's public
//! interface

mod kind;
#[cfg(test)]
mod kind_tests;
mod layer;
#[cfg(test)]
mod layer_tests;
use kind::parse_plugin_kind;
pub(crate) use layer::Layer;
use layer::LayerRaw;
use serde::Deserialize;

use super::args::SerializedArgs;
use super::error::{ConfigError, ConfigErrorCollector};
use crate::redaction::Redacted;

/// Service configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone)]
#[serde(default, deny_unknown_fields)]
pub(super) struct ServiceRaw {
  name: String,
  kind: String,
  args: SerializedArgs,
  layers: Vec<LayerRaw>,
}

impl std::fmt::Debug for ServiceRaw {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("ServiceRaw")
      .field("name", &self.name)
      .field("kind", &self.kind)
      .field("args", &Redacted(&self.args))
      .field("layers", &self.layers)
      .finish()
  }
}

/// Service configuration (after kind parsing).
#[derive(Default, Clone)]
pub(crate) struct Service {
  pub(in crate::config) name: String,
  pub(in crate::config) plugin_name: String,
  pub(in crate::config) kind: String,
  pub(in crate::config) args: SerializedArgs,
  pub(in crate::config) layers: Vec<Layer>,
}

impl std::fmt::Debug for Service {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("Service")
      .field("name", &self.name)
      .field("plugin_name", &self.plugin_name)
      .field("kind", &self.kind)
      .field("args", &Redacted(&self.args))
      .field("layers", &self.layers)
      .finish()
  }
}

impl Service {
  pub(crate) fn name(&self) -> &str {
    &self.name
  }

  pub(crate) fn plugin_name(&self) -> &str {
    &self.plugin_name
  }

  pub(crate) fn kind(&self) -> &str {
    &self.kind
  }

  pub(crate) fn args(&self) -> &SerializedArgs {
    &self.args
  }

  pub(crate) fn layers(&self) -> &[Layer] {
    &self.layers
  }
}

impl ServiceRaw {
  pub(super) fn parse(self) -> anyhow::Result<Service> {
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
pub(super) fn validate_service(
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
