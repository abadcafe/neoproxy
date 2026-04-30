//! Access log configuration types and validation.

use std::time::Duration;

use byte_unit::Byte;
use serde::Deserialize;

use super::{ConfigErrorCollector, ConfigErrorKind};

/// Log output format.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
  #[default]
  Text,
  Json,
}

/// Human-readable duration (e.g., "1s", "5m", "1h30m").
#[derive(Debug, Clone, Copy)]
pub struct HumanDuration(pub Duration);

impl<'de> Deserialize<'de> for HumanDuration {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    let duration = humantime::parse_duration(s.trim())
      .map_err(|e| serde::de::Error::custom(e.to_string()))?;
    Ok(HumanDuration(duration))
  }
}

fn default_enabled() -> bool {
  true
}

fn default_path_prefix() -> String {
  "access.log".to_string()
}

fn default_format() -> LogFormat {
  LogFormat::default()
}

fn default_buffer_size() -> Byte {
  Byte::from_u64(32 * 1024)
}

fn default_flush_interval() -> HumanDuration {
  HumanDuration(Duration::from_secs(1))
}

fn default_max_size() -> Byte {
  Byte::from_u64(200 * 1024 * 1024)
}

/// Full access log config with all fields resolved (used as top-level config).
#[derive(Debug, Clone, Deserialize)]
pub struct AccessLogConfig {
  #[serde(default = "default_enabled")]
  pub enabled: bool,

  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,

  #[serde(default = "default_format")]
  pub format: LogFormat,

  #[serde(default = "default_buffer_size")]
  pub buffer: Byte,

  #[serde(default = "default_flush_interval")]
  pub flush: HumanDuration,

  #[serde(default = "default_max_size")]
  pub max_size: Byte,
}

impl Default for AccessLogConfig {
  fn default() -> Self {
    Self {
      enabled: default_enabled(),
      path_prefix: default_path_prefix(),
      format: default_format(),
      buffer: default_buffer_size(),
      flush: default_flush_interval(),
      max_size: default_max_size(),
    }
  }
}

impl AccessLogConfig {
  /// Merge with a server-level override config.
  /// Only fields explicitly set in the override (Some) take precedence.
  /// Fields not set in the override (None) are inherited from self.
  pub fn merge(&self, override_config: &AccessLogOverride) -> Self {
    Self {
      enabled: override_config.enabled.unwrap_or(self.enabled),
      path_prefix: override_config
        .path_prefix
        .clone()
        .unwrap_or_else(|| self.path_prefix.clone()),
      format: override_config.format.unwrap_or(self.format),
      buffer: override_config.buffer.unwrap_or(self.buffer),
      flush: override_config.flush.unwrap_or(self.flush),
      max_size: override_config.max_size.unwrap_or(self.max_size),
    }
  }
}

/// Server-level access log override config.
/// All fields are Option so that only explicitly set fields
/// override the top-level config. Unset fields are inherited.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AccessLogOverride {
  pub enabled: Option<bool>,
  pub path_prefix: Option<String>,
  pub format: Option<LogFormat>,
  pub buffer: Option<Byte>,
  pub flush: Option<HumanDuration>,
  pub max_size: Option<Byte>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_human_duration_ms() {
    let hd: HumanDuration = serde_yaml::from_str("500ms").unwrap();
    assert_eq!(hd.0, Duration::from_millis(500));
  }

  #[test]
  fn test_parse_human_duration_s() {
    let hd: HumanDuration = serde_yaml::from_str("1s").unwrap();
    assert_eq!(hd.0, Duration::from_secs(1));
  }

  #[test]
  fn test_parse_human_duration_m() {
    let hd: HumanDuration = serde_yaml::from_str("5m").unwrap();
    assert_eq!(hd.0, Duration::from_secs(300));
  }

  #[test]
  fn test_parse_human_duration_h() {
    let hd: HumanDuration = serde_yaml::from_str("1h").unwrap();
    assert_eq!(hd.0, Duration::from_secs(3600));
  }

  #[test]
  fn test_parse_human_duration_composite() {
    let hd: HumanDuration = serde_yaml::from_str("1h30m").unwrap();
    assert_eq!(hd.0, Duration::from_secs(3600 + 30 * 60));
  }

  #[test]
  fn test_parse_human_duration_lowercase_only() {
    let hd: HumanDuration = serde_yaml::from_str("1s").unwrap();
    assert_eq!(hd.0, Duration::from_secs(1));
    let result: Result<HumanDuration, _> = serde_yaml::from_str("1S");
    assert!(result.is_err(), "Uppercase units should not be supported");
  }

  #[test]
  fn test_parse_human_duration_invalid_unit() {
    let result: Result<HumanDuration, _> = serde_yaml::from_str("1x");
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_human_duration_no_number() {
    let result: Result<HumanDuration, _> = serde_yaml::from_str("ms");
    assert!(result.is_err());
  }

  #[test]
  fn test_log_format_default_is_text() {
    let fmt = LogFormat::default();
    assert!(matches!(fmt, LogFormat::Text));
  }

  #[test]
  fn test_log_format_deserialize_text() {
    let fmt: LogFormat = serde_yaml::from_str("text").unwrap();
    assert!(matches!(fmt, LogFormat::Text));
  }

  #[test]
  fn test_log_format_deserialize_json() {
    let fmt: LogFormat = serde_yaml::from_str("json").unwrap();
    assert!(matches!(fmt, LogFormat::Json));
  }

  #[test]
  fn test_access_log_config_defaults() {
    let config = AccessLogConfig::default();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "access.log");
    assert!(matches!(config.format, LogFormat::Text));
    assert_eq!(config.buffer.as_u64(), 32 * 1024);
    assert_eq!(config.flush.0, Duration::from_secs(1));
    assert_eq!(config.max_size.as_u64(), 200 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_full() {
    let yaml = r#"
enabled: true
path_prefix: "http_access.log"
format: json
buffer: 64KiB
flush: 3s
max_size: 100MiB
"#;
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "http_access.log");
    assert!(matches!(config.format, LogFormat::Json));
    assert_eq!(config.buffer.as_u64(), 64 * 1024);
    assert_eq!(config.flush.0, Duration::from_secs(3));
    assert_eq!(config.max_size.as_u64(), 100 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_partial() {
    let yaml = r#"
path_prefix: "custom.log"
format: json
"#;
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "custom.log");
    assert!(matches!(config.format, LogFormat::Json));
    assert_eq!(config.buffer.as_u64(), 32 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_empty() {
    let yaml = "{}";
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "access.log");
  }

  #[test]
  fn test_access_log_config_merge_override_all() {
    let base = AccessLogConfig::default();
    let override_config = AccessLogOverride {
      enabled: Some(false),
      path_prefix: Some("override.log".to_string()),
      format: Some(LogFormat::Json),
      buffer: Some(Byte::from_u64(64 * 1024)),
      flush: Some(HumanDuration(Duration::from_secs(5))),
      max_size: Some(Byte::from_u64(500 * 1024 * 1024)),
    };
    let merged = base.merge(&override_config);
    assert!(!merged.enabled);
    assert_eq!(merged.path_prefix, "override.log");
    assert!(matches!(merged.format, LogFormat::Json));
    assert_eq!(merged.buffer.as_u64(), 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(5));
    assert_eq!(merged.max_size.as_u64(), 500 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_merge_partial_override() {
    let base = AccessLogConfig {
      enabled: true,
      path_prefix: "base.log".to_string(),
      format: LogFormat::Text,
      buffer: Byte::from_u64(64 * 1024),
      flush: HumanDuration(Duration::from_secs(3)),
      max_size: Byte::from_u64(100 * 1024 * 1024),
    };
    let override_config = AccessLogOverride {
      enabled: None,
      path_prefix: Some("http_access.log".to_string()),
      format: None,
      buffer: None,
      flush: None,
      max_size: None,
    };
    let merged = base.merge(&override_config);
    assert_eq!(merged.path_prefix, "http_access.log");
    assert!(merged.enabled);
    assert!(matches!(merged.format, LogFormat::Text));
    assert_eq!(merged.buffer.as_u64(), 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(3));
    assert_eq!(merged.max_size.as_u64(), 100 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_merge_empty_override() {
    let base = AccessLogConfig {
      enabled: true,
      path_prefix: "base.log".to_string(),
      format: LogFormat::Json,
      buffer: Byte::from_u64(64 * 1024),
      flush: HumanDuration(Duration::from_secs(5)),
      max_size: Byte::from_u64(500 * 1024 * 1024),
    };
    let override_config = AccessLogOverride {
      enabled: None,
      path_prefix: None,
      format: None,
      buffer: None,
      flush: None,
      max_size: None,
    };
    let merged = base.merge(&override_config);
    assert!(merged.enabled);
    assert_eq!(merged.path_prefix, "base.log");
    assert!(matches!(merged.format, LogFormat::Json));
    assert_eq!(merged.buffer.as_u64(), 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(5));
    assert_eq!(merged.max_size.as_u64(), 500 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_override_deserialize_partial() {
    let yaml = r#"
path_prefix: "http_access.log"
format: json
"#;
    let override_config: AccessLogOverride =
      serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
      override_config.path_prefix,
      Some("http_access.log".to_string())
    );
    assert!(matches!(override_config.format, Some(LogFormat::Json)));
    assert!(override_config.enabled.is_none());
    assert!(override_config.buffer.is_none());
    assert!(override_config.flush.is_none());
    assert!(override_config.max_size.is_none());
  }

  #[test]
  fn test_access_log_override_deserialize_empty() {
    let yaml = "{}";
    let override_config: AccessLogOverride =
      serde_yaml::from_str(yaml).unwrap();
    assert!(override_config.enabled.is_none());
    assert!(override_config.path_prefix.is_none());
    assert!(override_config.format.is_none());
    assert!(override_config.buffer.is_none());
    assert!(override_config.flush.is_none());
    assert!(override_config.max_size.is_none());
  }
}

// =========================================================================
// Validation logic
// =========================================================================

/// Validate access log configuration.
pub fn validate_access_log_config(
  access_log: &AccessLogConfig,
  collector: &mut ConfigErrorCollector,
) {
  // Validate buffer minimum size (at least 1KB)
  if access_log.buffer.as_u64() < 1024 {
    collector.add(
      "access_log.buffer",
      format!(
        "buffer size must be at least 1KB, got {} bytes",
        access_log.buffer.as_u64()
      ),
      ConfigErrorKind::InvalidFormat,
    );
  }

  // Validate max_size minimum size (at least 1MB)
  if access_log.max_size.as_u64() < 1024 * 1024 {
    collector.add(
      "access_log.max_size",
      format!(
        "max_size must be at least 1MB, got {} bytes",
        access_log.max_size.as_u64()
      ),
      ConfigErrorKind::InvalidFormat,
    );
  }

  // Validate flush interval (at least 100ms)
  if access_log.flush.0 < Duration::from_millis(100) {
    collector.add(
      "access_log.flush",
      format!(
        "flush interval must be at least 100ms, got {:?}",
        access_log.flush.0
      ),
      ConfigErrorKind::InvalidFormat,
    );
  }

  // Validate path_prefix not empty
  if access_log.path_prefix.is_empty() {
    collector.add(
      "access_log.path_prefix",
      "path_prefix cannot be empty".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
  }
}

#[cfg(test)]
mod validation_tests {
  use super::*;

  #[test]
  fn test_validate_access_log_valid() {
    let config = AccessLogConfig::default();
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "Default config should be valid: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_buffer_too_small() {
    let config = AccessLogConfig {
      buffer: Byte::from_u64(512), // Less than 1KB
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("buffer size must be at least 1KB"));
    assert!(found);
  }

  #[test]
  fn test_validate_max_size_too_small() {
    let config = AccessLogConfig {
      max_size: Byte::from_u64(512 * 1024), // Less than 1MB
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("max_size must be at least 1MB"));
    assert!(found);
  }

  #[test]
  fn test_validate_flush_too_short() {
    let config = AccessLogConfig {
      flush: HumanDuration(Duration::from_millis(50)), // Less than 100ms
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.message.contains("flush interval must be at least 100ms")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_empty_path_prefix() {
    let config = AccessLogConfig {
      path_prefix: "".to_string(),
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("path_prefix cannot be empty"));
    assert!(found);
  }

  #[test]
  fn test_validate_boundary_buffer_1kb() {
    let config = AccessLogConfig {
      buffer: Byte::from_u64(1024), // Exactly 1KB - should be valid
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    let buffer_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.message.contains("buffer size"))
      .collect();
    assert!(buffer_errors.is_empty(), "1KB should be valid");
  }

  #[test]
  fn test_validate_boundary_max_size_1mb() {
    let config = AccessLogConfig {
      max_size: Byte::from_u64(1024 * 1024), // Exactly 1MB - should be valid
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    let max_size_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.message.contains("max_size"))
      .collect();
    assert!(max_size_errors.is_empty(), "1MB should be valid");
  }

  #[test]
  fn test_validate_boundary_flush_100ms() {
    let config = AccessLogConfig {
      flush: HumanDuration(Duration::from_millis(100)), // Exactly 100ms
      ..Default::default()
    };
    let mut collector = ConfigErrorCollector::new();
    validate_access_log_config(&config, &mut collector);
    let flush_errors: Vec<_> = collector
      .errors()
      .iter()
      .filter(|e| e.message.contains("flush interval"))
      .collect();
    assert!(flush_errors.is_empty(), "100ms should be valid");
  }
}
