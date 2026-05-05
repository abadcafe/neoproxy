#![allow(clippy::borrowed_box)]
use std::collections::HashMap;

use anyhow::Result;

use crate::config::SerializedArgs;
use crate::plugin;
use crate::service::{Layer, Service};

pub mod access_log;
pub mod auth;
pub mod connect_tcp;
pub mod echo;
pub mod http3_chain;
pub mod tunnel;

/// Manages plugin lifecycle: registers all plugins at construction,
/// builds services/layers on demand.
pub struct PluginManager {
  plugins: HashMap<&'static str, Box<dyn plugin::Plugin>>,
}

impl PluginManager {
  pub fn new() -> Self {
    let mut plugins: HashMap<&'static str, Box<dyn plugin::Plugin>> =
      HashMap::new();
    plugins
      .insert(connect_tcp::plugin_name(), connect_tcp::create_plugin());
    plugins.insert(echo::plugin_name(), echo::create_plugin());
    plugins
      .insert(http3_chain::plugin_name(), http3_chain::create_plugin());
    plugins.insert(auth::plugin_name(), auth::create_plugin());
    plugins.insert(
      access_log::AccessLogPlugin::plugin_name(),
      access_log::AccessLogPlugin::create_plugin(),
    );
    Self { plugins }
  }

  pub async fn uninstall_all(&mut self) {
    for (_, plugin) in self.plugins.drain() {
      plugin.uninstall().await;
    }
  }

  pub fn build_service(
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

  /// Get a mutable reference to the plugin map.
  ///
  /// Used in tests to inject custom plugins.
  #[cfg(test)]
  pub fn plugins_mut(
    &mut self,
  ) -> &mut HashMap<&'static str, Box<dyn plugin::Plugin>> {
    &mut self.plugins
  }

  pub fn build_layer(
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_auth_plugin_name_and_create() {
    assert_eq!(auth::plugin_name(), "auth");
    let plugin = auth::create_plugin();
    assert!(plugin.layer_builder("basic_auth").is_some());
  }

  #[test]
  fn test_plugin_manager_new_has_all_plugins() {
    let pm = PluginManager::new();
    assert!(pm.plugins.contains_key("echo"));
    assert!(pm.plugins.contains_key("auth"));
    assert!(pm.plugins.contains_key("access_log"));
    assert!(pm.plugins.contains_key("http3_chain"));
    assert!(pm.plugins.contains_key("connect_tcp"));
  }

  #[test]
  fn test_plugin_manager_build_service_not_found() {
    let pm = PluginManager::new();
    let result =
      pm.build_service("nonexistent", "svc", serde_yaml::Value::Null);
    assert!(result.is_err());
    assert!(
      result
        .unwrap_err()
        .to_string()
        .contains("plugin 'nonexistent' not found")
    );
  }

  #[test]
  fn test_plugin_manager_build_layer_not_found() {
    let pm = PluginManager::new();
    let result =
      pm.build_layer("nonexistent", "layer", serde_yaml::Value::Null);
    assert!(result.is_err());
  }
}
