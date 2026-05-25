#![allow(clippy::borrowed_box)]
use std::collections::HashMap;

use anyhow::Result;
use tracing::warn;

use crate::config::SerializedArgs;
use crate::plugin;
use crate::service::{Layer, Service};

pub mod access_log;
pub mod auth;
pub mod echo;
pub mod http_upstream;
#[cfg(feature = "js-sandbox")]
pub mod js_sandbox;
pub mod utils;

type CreateFn = fn(Option<&SerializedArgs>) -> Box<dyn plugin::Plugin>;

/// Manages plugin lifecycle: only loads plugins listed in config,
/// builds services/layers on demand.
pub struct PluginManager {
  plugins: HashMap<String, Box<dyn plugin::Plugin>>,
}

impl PluginManager {
  pub fn new(plugins_config: HashMap<String, SerializedArgs>) -> Self {
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

    for (name, args) in plugins_config {
      match known_plugins.iter().find(|(n, _)| *n == name.as_str()) {
        Some((_, create_fn)) => {
          plugins.insert(name, create_fn(Some(&args)));
        }
        None => {
          warn!("unknown plugin '{}' in config, ignored", name);
        }
      }
    }

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
  ) -> &mut HashMap<String, Box<dyn plugin::Plugin>> {
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

  #[cfg(feature = "js-sandbox")]
  fn all_plugins_config() -> HashMap<String, SerializedArgs> {
    const ALL_PLUGINS: &[&str] = &[
      "echo", "auth", "access_log", "http_upstream", "js_sandbox",
    ];
    let mut m = HashMap::new();
    for &name in ALL_PLUGINS {
      let cfg = if name == "js_sandbox" {
        serde_yaml::from_str(r#"source_dir: "/tmp/js_sandbox""#).unwrap()
      } else {
        serde_yaml::Value::Null
      };
      m.insert(name.to_string(), cfg);
    }
    m
  }

  #[test]
  fn test_auth_plugin_name_and_create() {
    assert_eq!(auth::plugin_name(), "auth");
    let plugin = auth::create_plugin(None);
    assert!(plugin.layer_builder("basic_auth").is_some());
  }

  #[test]
  fn test_plugin_manager_empty_config_loads_nothing() {
    let pm = PluginManager::new(HashMap::new());
    assert!(pm.plugins.is_empty());
  }

  #[cfg(feature = "js-sandbox")]
  #[test]
  fn test_plugin_manager_all_plugins_config() {
    const ALL_PLUGINS: &[&str] = &[
      "echo", "auth", "access_log", "http_upstream", "js_sandbox",
    ];
    let pm = PluginManager::new(all_plugins_config());
    for &name in ALL_PLUGINS {
      assert!(
        pm.plugins.contains_key(name),
        "missing plugin '{}'",
        name
      );
    }
  }

  #[test]
  fn test_plugin_manager_partial_config() {
    let mut config = HashMap::new();
    config.insert("echo".to_string(), serde_yaml::Value::Null);
    config.insert("auth".to_string(), serde_yaml::Value::Null);
    let pm = PluginManager::new(config);
    assert!(pm.plugins.contains_key("echo"));
    assert!(pm.plugins.contains_key("auth"));
    assert!(!pm.plugins.contains_key("access_log"));
    assert!(!pm.plugins.contains_key("http_upstream"));
    assert!(!pm.plugins.contains_key("js_sandbox"));
  }

  #[test]
  fn test_plugin_manager_unknown_plugin_ignored() {
    let mut config = HashMap::new();
    config.insert("echo".to_string(), serde_yaml::Value::Null);
    config.insert("nonexistent".to_string(), serde_yaml::Value::Null);
    let pm = PluginManager::new(config);
    assert!(pm.plugins.contains_key("echo"));
    assert!(!pm.plugins.contains_key("nonexistent"));
    assert_eq!(pm.plugins.len(), 1);
  }

  #[test]
  fn test_plugin_manager_null_config_value() {
    let mut config = HashMap::new();
    config.insert("echo".to_string(), serde_yaml::Value::Null);
    let pm = PluginManager::new(config);
    assert!(pm.plugins.contains_key("echo"));
  }

  #[test]
  fn test_plugin_manager_build_service_not_found() {
    let pm = PluginManager::new(HashMap::new());
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
  fn test_plugin_manager_build_service_unconfigured_plugin() {
    let mut config = HashMap::new();
    config.insert("echo".to_string(), serde_yaml::Value::Null);
    let pm = PluginManager::new(config);
    let result =
      pm.build_service("auth", "basic_auth", serde_yaml::Value::Null);
    assert!(result.is_err());
    assert!(
      result
        .unwrap_err()
        .to_string()
        .contains("plugin 'auth' not found")
    );
  }

  #[test]
  fn test_plugin_manager_build_layer_not_found() {
    let pm = PluginManager::new(HashMap::new());
    let result =
      pm.build_layer("nonexistent", "layer", serde_yaml::Value::Null);
    assert!(result.is_err());
  }

  #[test]
  fn test_plugin_manager_build_service_with_configured_plugin() {
    let mut config = HashMap::new();
    config.insert("echo".to_string(), serde_yaml::Value::Null);
    let pm = PluginManager::new(config);
    let result =
      pm.build_service("echo", "echo", serde_yaml::Value::Null);
    assert!(result.is_ok());
  }

  #[test]
  fn test_plugin_manager_build_layer_with_configured_plugin() {
    let mut config = HashMap::new();
    config.insert("auth".to_string(), serde_yaml::Value::Null);
    let pm = PluginManager::new(config);
    let args: SerializedArgs =
      serde_yaml::from_str(r"users: []").unwrap();
    let result = pm.build_layer("auth", "basic_auth", args);
    assert!(result.is_ok());
  }
}
