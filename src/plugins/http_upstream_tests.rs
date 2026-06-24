use super::http_upstream::{create_plugin, plugin_name};

#[test]
fn test_plugin_name_returns_http_upstream() {
  assert_eq!(plugin_name(), "http_upstream");
}

#[test]
fn test_create_plugin_without_config_registers_upstream_builder() {
  let plugin = create_plugin(None).unwrap();

  assert!(plugin.service_builder("upstream").is_some());
  assert!(plugin.service_builder("missing").is_none());
}
