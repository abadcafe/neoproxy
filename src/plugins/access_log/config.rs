//! Access log plugin configuration.

use std::time::Duration;

use byte_unit::Byte;
use serde::{Deserialize, Serialize};

use super::context::LogFormat;

/// Default values.
const DEFAULT_PATH_PREFIX: &str = "logs/access";
const DEFAULT_BUFFER_CAPACITY: u64 = 32 * 1024;
const DEFAULT_MAX_BUFFER_SIZE: u64 = 128 * 1024;
const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 1;
const DEFAULT_MAX_FILE_SIZE: u64 = 200 * 1024 * 1024;
const DEFAULT_ROTATE_DAILY: bool = true;

fn default_path_prefix() -> String {
  DEFAULT_PATH_PREFIX.to_string()
}

fn default_buffer_capacity() -> Byte {
  Byte::from_u64(DEFAULT_BUFFER_CAPACITY)
}

fn default_max_buffer_size() -> Byte {
  Byte::from_u64(DEFAULT_MAX_BUFFER_SIZE)
}

fn default_flush_interval() -> Duration {
  Duration::from_secs(DEFAULT_FLUSH_INTERVAL_SECS)
}

fn default_max_file_size() -> Byte {
  Byte::from_u64(DEFAULT_MAX_FILE_SIZE)
}

fn default_rotate_daily() -> bool {
  DEFAULT_ROTATE_DAILY
}

/// Configuration for a single named access log writer.
///
/// `path_prefix` is the unique key for each writer. The actual log file
/// is `{path_prefix}.{date}` when `rotate_daily` is enabled, or
/// `{path_prefix}` when `rotate_daily` is false.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AccessLogWriterConfig {
  /// Unique key and file path prefix.
  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,
  /// Flush-triggering buffer size.
  #[serde(default = "default_buffer_capacity")]
  pub buffer_capacity: Byte,
  /// Max buffer; drops entries when full.
  #[serde(default = "default_max_buffer_size")]
  pub max_buffer_size: Byte,
  /// Max time between flushes.
  #[serde(with = "humantime_serde", default = "default_flush_interval")]
  pub flush_interval: Duration,
  /// Max file size before rotation.
  #[serde(default = "default_max_file_size")]
  pub max_file_size: Byte,
  /// Rotate at date boundary.
  #[serde(default = "default_rotate_daily")]
  pub rotate_daily: bool,
  /// Log format (text / json).
  #[serde(default)]
  pub format: LogFormat,
}

impl Default for AccessLogWriterConfig {
  fn default() -> Self {
    Self {
      path_prefix: default_path_prefix(),
      buffer_capacity: default_buffer_capacity(),
      max_buffer_size: default_max_buffer_size(),
      flush_interval: default_flush_interval(),
      max_file_size: default_max_file_size(),
      rotate_daily: default_rotate_daily(),
      format: LogFormat::default(),
    }
  }
}

/// Access log plugin-level configuration (the `plugins.access_log` section).
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AccessLogPluginConfig {
  /// List of named writer configurations.
  pub writers: Vec<AccessLogWriterConfig>,
}

/// Configuration for the access_log.file layer.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
  /// Writer path prefix to log to (matches `writers[].path_prefix`).
  pub writer: String,
  /// Context fields to include in log entries.
  #[serde(default)]
  pub context_fields: Vec<String>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_writer_config_default_values() {
    let yaml = r#"
path_prefix: "logs/audit"
"#;
    let config: AccessLogWriterConfig = serde_yaml::from_str(yaml).unwrap();
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
    let config: AccessLogWriterConfig = serde_yaml::from_str(yaml).unwrap();
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
    let config: AccessLogPluginConfig = serde_yaml::from_str(yaml).unwrap();
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
    // writer is required (no #[serde(default)]), so deserialization must fail
    // when the field is missing
    assert!(result.is_err());
  }

  #[test]
  fn test_writer_config_default_path_prefix() {
    let config = AccessLogWriterConfig::default();
    assert_eq!(config.path_prefix, "logs/access");
  }
}
