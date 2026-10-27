use std::collections::HashMap;

use crate::config::SerializedArgs;
use crate::plugins::{PluginManager, auth};

fn all_plugins_config() -> HashMap<String, SerializedArgs> {
  const ALL_PLUGINS: &[&str] =
    &["echo", "auth", "access_log", "upstream"];
  let mut m = HashMap::new();
  for &name in ALL_PLUGINS {
    let cfg = serde_yaml::Value::Null;
    m.insert(name.to_string(), cfg);
  }
  m
}

#[test]
fn test_auth_plugin_name_and_create() {
  assert_eq!(auth::plugin_name(), "auth");
  let plugin = auth::create_plugin(None).unwrap();
  assert!(plugin.layer_builder("basic_auth").is_some());
}

#[test]
fn test_plugin_manager_empty_config_loads_nothing() {
  let (pm, _errors) = PluginManager::new(HashMap::new(), None);
  assert!(pm.plugins.is_empty());
}

#[test]
fn test_plugin_manager_all_plugins_config() {
  const ALL_PLUGINS: &[&str] =
    &["echo", "auth", "access_log", "upstream"];
  let (pm, errors) = PluginManager::new(all_plugins_config(), None);
  assert!(errors.is_empty());
  for &name in ALL_PLUGINS {
    assert!(pm.plugins.contains_key(name), "missing plugin '{}'", name);
  }
}

#[test]
fn test_plugin_manager_partial_config() {
  let mut config = HashMap::new();
  config.insert("echo".to_string(), serde_yaml::Value::Null);
  config.insert("auth".to_string(), serde_yaml::Value::Null);
  let (pm, _errors) = PluginManager::new(config, None);
  assert!(pm.plugins.contains_key("echo"));
  assert!(pm.plugins.contains_key("auth"));
  assert!(!pm.plugins.contains_key("access_log"));
  assert!(!pm.plugins.contains_key("upstream"));
}

#[test]
fn test_plugin_manager_unknown_plugin_is_reported() {
  let mut config = HashMap::new();
  config.insert("echo".to_string(), serde_yaml::Value::Null);
  config.insert("nonexistent".to_string(), serde_yaml::Value::Null);
  let (pm, errors) = PluginManager::new(config, None);
  assert!(pm.plugins.contains_key("echo"));
  assert!(!pm.plugins.contains_key("nonexistent"));
  assert_eq!(pm.plugins.len(), 1);
  assert_eq!(errors.len(), 1);
}

#[test]
fn test_plugin_manager_null_config_value() {
  let mut config = HashMap::new();
  config.insert("echo".to_string(), serde_yaml::Value::Null);
  let (pm, _errors) = PluginManager::new(config, None);
  assert!(pm.plugins.contains_key("echo"));
}

#[test]
fn test_plugin_manager_build_service_not_found() {
  let (pm, _errors) = PluginManager::new(HashMap::new(), None);
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
  let (pm, _errors) = PluginManager::new(config, None);
  let result =
    pm.build_service("auth", "basic_auth", serde_yaml::Value::Null);
  assert!(result.is_err());
  assert!(
    result.unwrap_err().to_string().contains("plugin 'auth' not found")
  );
}

#[test]
fn test_plugin_manager_build_layer_not_found() {
  let (pm, _errors) = PluginManager::new(HashMap::new(), None);
  let result =
    pm.build_layer("nonexistent", "layer", serde_yaml::Value::Null);
  assert!(result.is_err());
}

#[test]
fn test_plugin_manager_build_service_with_configured_plugin() {
  let mut config = HashMap::new();
  config.insert("echo".to_string(), serde_yaml::Value::Null);
  let (pm, _errors) = PluginManager::new(config, None);
  let result =
    pm.build_service("echo", "echo", serde_yaml::Value::Null);
  assert!(result.is_ok());
}

#[test]
fn test_plugin_manager_build_layer_with_configured_plugin() {
  let mut config = HashMap::new();
  config.insert("auth".to_string(), serde_yaml::Value::Null);
  let (pm, _errors) = PluginManager::new(config, None);
  let args: SerializedArgs = serde_yaml::from_str(
    "users: [{username: admin, password: secret}]",
  )
  .unwrap();
  let result = pm.build_layer("auth", "basic_auth", args);
  assert!(result.is_ok());
}
