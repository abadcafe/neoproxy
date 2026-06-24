//! Plugin registry and lifecycle management.
//!
//! module: plugins
//! responsibilities: manage plugin loading, service/layer building, and
//! shutdown public operations: PluginManager::new,
//! PluginManager::build_service, PluginManager::build_layer,
//! PluginManager::uninstall_all data entities: PluginManager,
//! PluginLoadError tests: plugins_tests.rs

use std::collections::HashMap;

use anyhow::Result;
use tracing::warn;

use crate::config::SerializedArgs;
use crate::plugin;
use crate::service::{Layer, Service};

pub(crate) mod access_log;
#[cfg(test)]
mod access_log_tests;
pub(crate) mod auth;
#[cfg(test)]
mod auth_tests;
pub(crate) mod echo;
#[cfg(test)]
mod echo_tests;
pub(crate) mod http_upstream;
#[cfg(feature = "js-sandbox")]
pub(crate) mod js_sandbox;

type CreateFn =
  fn(Option<&SerializedArgs>) -> Result<Box<dyn plugin::Plugin>>;

/// Error from a single plugin failing to load.
pub(crate) struct PluginLoadError {
  pub(crate) name: String,
  pub(crate) source: anyhow::Error,
}

/// Manages plugin lifecycle: only loads plugins listed in config,
/// builds services/layers on demand.
pub(crate) struct PluginManager {
  pub(crate) plugins: HashMap<String, Box<dyn plugin::Plugin>>,
}

impl PluginManager {
  pub(crate) fn new(
    plugins_config: HashMap<String, SerializedArgs>,
  ) -> (Self, Vec<PluginLoadError>) {
    let known_plugins: &[(&str, CreateFn)] = &[
      (echo::plugin_name(), echo::create_plugin),
      (auth::plugin_name(), auth::create_plugin),
      (access_log::plugin_name(), access_log::create_plugin),
      (http_upstream::plugin_name(), http_upstream::create_plugin),
      #[cfg(feature = "js-sandbox")]
      (js_sandbox::plugin_name(), js_sandbox::create_plugin),
    ];

    let mut plugins: HashMap<String, Box<dyn plugin::Plugin>> =
      HashMap::new();
    let mut errors = Vec::new();

    for (name, args) in plugins_config {
      match known_plugins.iter().find(|(n, _)| *n == name.as_str()) {
        Some((_, create_fn)) => match create_fn(Some(&args)) {
          Ok(plugin) => {
            plugins.insert(name, plugin);
          }
          Err(e) => {
            warn!("plugin '{}' failed to load: {}", name, e);
            errors.push(PluginLoadError { name, source: e });
          }
        },
        None => {
          warn!("unknown plugin '{}' in config, ignored", name);
        }
      }
    }

    (Self { plugins }, errors)
  }

  pub(crate) async fn uninstall_all(&mut self) {
    for (_, plugin) in self.plugins.drain() {
      plugin.uninstall().await;
    }
  }

  pub(crate) fn build_service(
    &self,
    plugin_name: &str,
    service_name: &str,
    args: SerializedArgs,
  ) -> Result<Service> {
    let plugin = self.plugins.get(plugin_name).ok_or_else(|| {
      anyhow::anyhow!("plugin '{}' not found", plugin_name)
    })?;
    let builder =
      plugin.service_builder(service_name).ok_or_else(|| {
        anyhow::anyhow!(
          "service '{}' not found in plugin '{}'",
          service_name,
          plugin_name
        )
      })?;
    builder(args)
  }

  pub(crate) fn build_layer(
    &self,
    plugin_name: &str,
    layer_name: &str,
    args: SerializedArgs,
  ) -> Result<Layer> {
    let plugin = self.plugins.get(plugin_name).ok_or_else(|| {
      anyhow::anyhow!("plugin '{}' not found", plugin_name)
    })?;
    let builder =
      plugin.layer_builder(layer_name).ok_or_else(|| {
        anyhow::anyhow!(
          "layer '{}' not found in plugin '{}'",
          layer_name,
          plugin_name
        )
      })?;
    builder(args)
  }
}
