//! module: layer
//! responsibilities: parse and expose configured service middleware
//! layers public operations: Layer accessors and Debug, LayerRaw::parse
//! data entities: Layer, LayerRaw
//! tests: layer_tests.rs
use serde::Deserialize;

use super::kind::parse_plugin_kind;
use crate::config::args::SerializedArgs;
use crate::redaction::Redacted;

/// Layer configuration (raw, before kind parsing).
#[derive(Deserialize, Default, Clone)]
#[serde(default, deny_unknown_fields)]
pub(super) struct LayerRaw {
  kind: String,
  args: SerializedArgs,
}

impl std::fmt::Debug for LayerRaw {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("LayerRaw")
      .field("kind", &self.kind)
      .field("args", &Redacted(&self.args))
      .finish()
  }
}

/// Layer configuration (after kind parsing).
#[derive(Default, Clone)]
pub(crate) struct Layer {
  pub(in crate::config) plugin_name: String,
  pub(in crate::config) kind: String,
  pub(in crate::config) args: SerializedArgs,
}

impl std::fmt::Debug for Layer {
  fn fmt(
    &self,
    formatter: &mut std::fmt::Formatter<'_>,
  ) -> std::fmt::Result {
    formatter
      .debug_struct("Layer")
      .field("plugin_name", &self.plugin_name)
      .field("kind", &self.kind)
      .field("args", &Redacted(&self.args))
      .finish()
  }
}

impl Layer {
  pub(crate) fn plugin_name(&self) -> &str {
    &self.plugin_name
  }

  pub(crate) fn kind(&self) -> &str {
    &self.kind
  }

  pub(crate) fn args(&self) -> &SerializedArgs {
    &self.args
  }
}

impl LayerRaw {
  pub(super) fn parse(self) -> anyhow::Result<Layer> {
    let (plugin_name, kind) = parse_plugin_kind(&self.kind, "layer")?;
    Ok(Layer { plugin_name, kind, args: self.args })
  }
}
