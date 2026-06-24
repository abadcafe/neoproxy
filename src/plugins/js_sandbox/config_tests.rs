use super::config::PluginConfig;

#[test]
fn test_plugin_config_deserializes_defaults() {
  let config: PluginConfig =
    serde_yaml::from_str(r#"source_dir: "/tmp/js""#).unwrap();

  assert_eq!(config.source_dir, "/tmp/js");
  assert_eq!(config.worker_threads, 100);
  assert_eq!(config.default_cpu_limit_ms, 5000);
  assert_eq!(config.default_mem_limit_mb, 128);
}

#[test]
fn test_plugin_config_deserializes_custom_limits() {
  let config: PluginConfig = serde_yaml::from_str(
    r#"
source_dir: "/tmp/js"
worker_threads: 2
default_cpu_limit_ms: 100
default_mem_limit_mb: 64
"#,
  )
  .unwrap();

  assert_eq!(config.worker_threads, 2);
  assert_eq!(config.default_cpu_limit_ms, 100);
  assert_eq!(config.default_mem_limit_mb, 64);
}
