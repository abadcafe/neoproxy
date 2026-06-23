use std::time::Duration;

use byte_unit::Byte;

use super::config::*;
use super::context::LogFormat;

#[test]
fn test_writer_config_default_values() {
  let yaml = r#"
path_prefix: "logs/audit"
"#;
  let config: AccessLogWriterConfig =
    serde_yaml::from_str(yaml).unwrap();
  assert_eq!(config.path_prefix, "logs/audit");
  assert_eq!(config.buffer_capacity, Byte::from_u64(32 * 1024));
  assert_eq!(config.max_buffer_size, Byte::from_u64(128 * 1024));
  assert_eq!(config.flush_interval, Duration::from_secs(1));
  assert_eq!(config.max_file_size, Byte::from_u64(200 * 1024 * 1024));
  assert!(config.rotate_daily);
  assert_eq!(config.format, LogFormat::Text);
}

#[test]
fn test_writer_config_custom_values() {
  let yaml = r#"
path_prefix: "logs/audit"
buffer_capacity: "64KiB"
max_buffer_size: "256KiB"
flush_interval: "5s"
max_file_size: "500MiB"
rotate_daily: false
format: "json"
"#;
  let config: AccessLogWriterConfig =
    serde_yaml::from_str(yaml).unwrap();
  assert_eq!(config.path_prefix, "logs/audit");
  assert_eq!(config.buffer_capacity, Byte::from_u64(64 * 1024));
  assert_eq!(config.max_buffer_size, Byte::from_u64(256 * 1024));
  assert_eq!(config.flush_interval, Duration::from_secs(5));
  assert_eq!(config.max_file_size, Byte::from_u64(500 * 1024 * 1024));
  assert!(!config.rotate_daily);
  assert_eq!(config.format, LogFormat::Json);
}

#[test]
fn test_plugin_config_with_writers() {
  let yaml = r#"
writers:
- path_prefix: "logs/default_access"
- path_prefix: "logs/audit"
  format: "json"
"#;
  let config: AccessLogPluginConfig =
    serde_yaml::from_str(yaml).unwrap();
  assert_eq!(config.writers.len(), 2);
  assert_eq!(config.writers[0].path_prefix, "logs/default_access");
  assert_eq!(config.writers[1].path_prefix, "logs/audit");
  assert_eq!(config.writers[1].format, LogFormat::Json);
}

#[test]
fn test_plugin_config_default_empty_writers() {
  let config = AccessLogPluginConfig::default();
  assert!(config.writers.is_empty());
}

#[test]
fn test_access_log_config_with_writer() {
  let yaml = r#"
writer: "logs/audit"
context_fields:
- basic_auth.user
"#;
  let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
  assert_eq!(config.writer, "logs/audit");
  assert_eq!(config.context_fields.len(), 1);
}

#[test]
fn test_access_log_config_writer_required() {
  let yaml = r#"
context_fields:
- basic_auth.user
"#;
  let result: Result<AccessLogConfig, _> = serde_yaml::from_str(yaml);
  // writer is required (no #[serde(default)]), so deserialization
  // must fail when the field is missing
  assert!(result.is_err());
}

#[test]
fn test_writer_config_default_path_prefix() {
  let config = AccessLogWriterConfig::default();
  assert_eq!(config.path_prefix, "logs/access");
}
