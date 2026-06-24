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
pub(crate) struct AccessLogWriterConfig {
  /// Unique key and file path prefix.
  #[serde(default = "default_path_prefix")]
  pub(crate) path_prefix: String,
  /// Flush-triggering buffer size.
  #[serde(default = "default_buffer_capacity")]
  pub(crate) buffer_capacity: Byte,
  /// Max buffer; drops entries when full.
  #[serde(default = "default_max_buffer_size")]
  pub(crate) max_buffer_size: Byte,
  /// Max time between flushes.
  #[serde(
    with = "humantime_serde",
    default = "default_flush_interval"
  )]
  pub(crate) flush_interval: Duration,
  /// Max file size before rotation.
  #[serde(default = "default_max_file_size")]
  pub(crate) max_file_size: Byte,
  /// Rotate at date boundary.
  #[serde(default = "default_rotate_daily")]
  pub(crate) rotate_daily: bool,
  /// Log format (text / json).
  #[serde(default)]
  pub(crate) format: LogFormat,
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

/// Access log plugin-level configuration (the `plugins.access_log`
/// section).
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AccessLogPluginConfig {
  /// List of named writer configurations.
  pub(crate) writers: Vec<AccessLogWriterConfig>,
}

/// Configuration for the access_log.file layer.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessLogConfig {
  /// Writer path prefix to log to (matches `writers[].path_prefix`).
  pub(crate) writer: String,
  /// Context fields to include in log entries.
  #[serde(default)]
  pub(crate) context_fields: Vec<String>,
}
