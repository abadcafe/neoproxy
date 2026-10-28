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
pub(crate) mod upstream;
#[cfg(test)]
mod upstream_tests;

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
  #[cfg(test)]
  pub(crate) fn new(
    plugins_config: HashMap<String, SerializedArgs>,
    log_registry: Option<
      std::sync::Arc<access_log::registry::WriterRegistry>,
    >,
  ) -> (Self, Vec<PluginLoadError>) {
    Self::with_upstream(plugins_config, log_registry, None)
  }

  pub(crate) fn with_upstream(
    plugins_config: HashMap<String, SerializedArgs>,
    log_registry: Option<
      std::sync::Arc<access_log::registry::WriterRegistry>,
    >,
    connection_pools: Option<std::sync::Arc<upstream::ConnectionPools>>,
  ) -> (Self, Vec<PluginLoadError>) {
    let known_plugins: &[(&str, CreateFn)] = &[
      (echo::plugin_name(), echo::create_plugin),
      (auth::plugin_name(), auth::create_plugin),
      (access_log::plugin_name(), access_log::create_plugin),
      (upstream::plugin_name(), upstream::create_plugin),
    ];

    let mut plugins: HashMap<String, Box<dyn plugin::Plugin>> =
      HashMap::new();
    let mut errors = Vec::new();

    for (name, args) in plugins_config {
      if name == access_log::plugin_name()
        && let Some(registry) = &log_registry
      {
        plugins.insert(
          name,
          access_log::create_shared_plugin(registry.clone()),
        );
        continue;
      }
      if name == upstream::plugin_name()
        && let Some(shared) = &connection_pools
      {
        match upstream::create_pooled_plugin(
          Some(&args),
          shared.clone(),
        ) {
          Ok(plugin) => {
            plugins.insert(name, plugin);
          }
          Err(source) => errors.push(PluginLoadError { name, source }),
        }
        continue;
      }
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
          errors.push(PluginLoadError {
            name: name.clone(),
            source: anyhow::anyhow!("unknown plugin '{name}'"),
          });
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
