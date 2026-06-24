use super::js_sandbox::{create_plugin, plugin_name};

#[test]
fn test_plugin_name_returns_js_sandbox() {
  assert_eq!(plugin_name(), "js_sandbox");
}

#[test]
fn test_create_plugin_without_config_is_rejected() {
  assert!(create_plugin(None).is_err());
}

#[test]
fn test_create_plugin_with_config_registers_sandbox_builder() {
  let dir = tempfile::tempdir().unwrap();
  let config = serde_yaml::to_value(serde_yaml::Mapping::from_iter([
    (
      serde_yaml::Value::String("source_dir".to_string()),
      serde_yaml::Value::String(
        dir.path().to_string_lossy().to_string(),
      ),
    ),
    (
      serde_yaml::Value::String("worker_threads".to_string()),
      serde_yaml::Value::Number(1.into()),
    ),
  ]))
  .unwrap();

  let plugin = create_plugin(Some(&config)).unwrap();

  assert!(plugin.service_builder("sandbox").is_some());
  assert!(plugin.service_builder("missing").is_none());
  futures::executor::block_on(plugin.uninstall());
}
