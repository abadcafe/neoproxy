use std::time::Duration;

use serde::{Deserialize, de};

/// Log output format.
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
  #[default]
  Text,
  Json,
}

/// Human-readable byte size (e.g., "32kb", "200mb").
#[derive(Debug, Clone, Copy)]
pub struct HumanBytes(pub u64);

/// Human-readable duration (e.g., "1s", "5m").
#[derive(Debug, Clone, Copy)]
pub struct HumanDuration(pub Duration);

fn parse_human_bytes(s: &str) -> Result<u64, String> {
  let s = s.trim().to_lowercase();
  if s.is_empty() {
    return Err("empty string".to_string());
  }

  // Find where digits end and unit begins
  let num_end =
    s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());

  if num_end == 0 {
    return Err(format!("no number found in '{s}'"));
  }

  let num: u64 =
    s[..num_end].parse().map_err(|e| format!("invalid number: {e}"))?;

  let unit = &s[num_end..];
  let multiplier: u64 = match unit {
    "" | "b" => 1,
    "kb" => 1024,
    "mb" => 1024 * 1024,
    "gb" => 1024 * 1024 * 1024,
    _ => return Err(format!("unknown unit '{unit}'")),
  };

  num
    .checked_mul(multiplier)
    .ok_or_else(|| "value overflow".to_string())
}

impl<'de> Deserialize<'de> for HumanBytes {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    let bytes = parse_human_bytes(&s).map_err(de::Error::custom)?;
    Ok(HumanBytes(bytes))
  }
}

fn parse_human_duration(s: &str) -> Result<Duration, String> {
  let s = s.trim().to_lowercase();
  if s.is_empty() {
    return Err("empty string".to_string());
  }

  let num_end =
    s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());

  if num_end == 0 {
    return Err(format!("no number found in '{s}'"));
  }

  let num: u64 =
    s[..num_end].parse().map_err(|e| format!("invalid number: {e}"))?;

  let unit = &s[num_end..];
  match unit {
    "ms" => Ok(Duration::from_millis(num)),
    "s" => Ok(Duration::from_secs(num)),
    "m" => num
      .checked_mul(60)
      .map(Duration::from_secs)
      .ok_or_else(|| "value overflow".to_string()),
    _ => Err(format!("unknown unit '{unit}'")),
  }
}

impl<'de> Deserialize<'de> for HumanDuration {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    let duration =
      parse_human_duration(&s).map_err(de::Error::custom)?;
    Ok(HumanDuration(duration))
  }
}

// ============== AccessLogConfig ==============

fn default_enabled() -> bool {
  true
}

fn default_path_prefix() -> String {
  "access.log".to_string()
}

fn default_format() -> LogFormat {
  LogFormat::default()
}

fn default_buffer_size() -> HumanBytes {
  HumanBytes(32 * 1024)
}

fn default_flush_interval() -> HumanDuration {
  HumanDuration(Duration::from_secs(1))
}

fn default_max_size() -> HumanBytes {
  HumanBytes(200 * 1024 * 1024)
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
  pub buffer: HumanBytes,

  #[serde(default = "default_flush_interval")]
  pub flush: HumanDuration,

  #[serde(default = "default_max_size")]
  pub max_size: HumanBytes,
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
  pub buffer: Option<HumanBytes>,
  pub flush: Option<HumanDuration>,
  pub max_size: Option<HumanBytes>,
}

#[cfg(test)]
mod tests {
  use super::*;

  // ============== HumanBytes Tests ==============

  #[test]
  fn test_parse_human_bytes_plain_number() {
    let hb: HumanBytes = serde_yaml::from_str("1024").unwrap();
    assert_eq!(hb.0, 1024);
  }

  #[test]
  fn test_parse_human_bytes_b_suffix() {
    let hb: HumanBytes = serde_yaml::from_str("512b").unwrap();
    assert_eq!(hb.0, 512);
  }

  #[test]
  fn test_parse_human_bytes_kb() {
    let hb: HumanBytes = serde_yaml::from_str("32kb").unwrap();
    assert_eq!(hb.0, 32 * 1024);
  }

  #[test]
  fn test_parse_human_bytes_mb() {
    let hb: HumanBytes = serde_yaml::from_str("200mb").unwrap();
    assert_eq!(hb.0, 200 * 1024 * 1024);
  }

  #[test]
  fn test_parse_human_bytes_gb() {
    let hb: HumanBytes = serde_yaml::from_str("1gb").unwrap();
    assert_eq!(hb.0, 1024 * 1024 * 1024);
  }

  #[test]
  fn test_parse_human_bytes_case_insensitive() {
    let hb: HumanBytes = serde_yaml::from_str("32KB").unwrap();
    assert_eq!(hb.0, 32 * 1024);
  }

  #[test]
  fn test_parse_human_bytes_with_spaces() {
    let hb: HumanBytes = serde_yaml::from_str("\" 32kb \"").unwrap();
    assert_eq!(hb.0, 32 * 1024);
  }

  #[test]
  fn test_parse_human_bytes_invalid_unit() {
    let result: Result<HumanBytes, _> = serde_yaml::from_str("32tb");
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_human_bytes_no_number() {
    let result: Result<HumanBytes, _> = serde_yaml::from_str("kb");
    assert!(result.is_err());
  }

  // ============== HumanDuration Tests ==============

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
  fn test_parse_human_duration_case_insensitive() {
    let hd: HumanDuration = serde_yaml::from_str("1S").unwrap();
    assert_eq!(hd.0, Duration::from_secs(1));
  }

  #[test]
  fn test_parse_human_duration_invalid_unit() {
    let result: Result<HumanDuration, _> = serde_yaml::from_str("1h");
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_human_duration_no_number() {
    let result: Result<HumanDuration, _> = serde_yaml::from_str("ms");
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_human_duration_minute_overflow() {
    // Test that large minute values that would overflow are rejected
    // u64::MAX / 60 = 307445734561825860, so anything larger should overflow
    let result: Result<HumanDuration, _> =
      serde_yaml::from_str("307445734561825861m");
    assert!(
      result.is_err(),
      "expected overflow error for large minute value"
    );
  }

  // ============== LogFormat Tests ==============

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

  // ============== AccessLogConfig Tests ==============

  #[test]
  fn test_access_log_config_defaults() {
    let config = AccessLogConfig::default();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "access.log");
    assert!(matches!(config.format, LogFormat::Text));
    assert_eq!(config.buffer.0, 32 * 1024);
    assert_eq!(config.flush.0, Duration::from_secs(1));
    assert_eq!(config.max_size.0, 200 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_full() {
    let yaml = r#"
enabled: true
path_prefix: "http_access.log"
format: json
buffer: 64kb
flush: 3s
max_size: 100mb
"#;
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "http_access.log");
    assert!(matches!(config.format, LogFormat::Json));
    assert_eq!(config.buffer.0, 64 * 1024);
    assert_eq!(config.flush.0, Duration::from_secs(3));
    assert_eq!(config.max_size.0, 100 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_deserialize_partial() {
    let yaml = r#"
path_prefix: "custom.log"
format: json
"#;
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    // Unspecified fields should use defaults
    assert!(config.enabled);
    assert_eq!(config.path_prefix, "custom.log");
    assert!(matches!(config.format, LogFormat::Json));
    assert_eq!(config.buffer.0, 32 * 1024);
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
      buffer: Some(HumanBytes(64 * 1024)),
      flush: Some(HumanDuration(Duration::from_secs(5))),
      max_size: Some(HumanBytes(500 * 1024 * 1024)),
    };
    let merged = base.merge(&override_config);
    assert!(!merged.enabled);
    assert_eq!(merged.path_prefix, "override.log");
    assert!(matches!(merged.format, LogFormat::Json));
    assert_eq!(merged.buffer.0, 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(5));
    assert_eq!(merged.max_size.0, 500 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_merge_partial_override() {
    let base = AccessLogConfig {
      enabled: true,
      path_prefix: "base.log".to_string(),
      format: LogFormat::Text,
      buffer: HumanBytes(64 * 1024),
      flush: HumanDuration(Duration::from_secs(3)),
      max_size: HumanBytes(100 * 1024 * 1024),
    };
    // Server-level only overrides path_prefix
    let override_config = AccessLogOverride {
      enabled: None,
      path_prefix: Some("http_access.log".to_string()),
      format: None,
      buffer: None,
      flush: None,
      max_size: None,
    };
    let merged = base.merge(&override_config);
    // Overridden field
    assert_eq!(merged.path_prefix, "http_access.log");
    // Inherited from base
    assert!(merged.enabled);
    assert!(matches!(merged.format, LogFormat::Text));
    assert_eq!(merged.buffer.0, 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(3));
    assert_eq!(merged.max_size.0, 100 * 1024 * 1024);
  }

  #[test]
  fn test_access_log_config_merge_empty_override() {
    let base = AccessLogConfig {
      enabled: true,
      path_prefix: "base.log".to_string(),
      format: LogFormat::Json,
      buffer: HumanBytes(64 * 1024),
      flush: HumanDuration(Duration::from_secs(5)),
      max_size: HumanBytes(500 * 1024 * 1024),
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
    // All fields inherited from base
    assert!(merged.enabled);
    assert_eq!(merged.path_prefix, "base.log");
    assert!(matches!(merged.format, LogFormat::Json));
    assert_eq!(merged.buffer.0, 64 * 1024);
    assert_eq!(merged.flush.0, Duration::from_secs(5));
    assert_eq!(merged.max_size.0, 500 * 1024 * 1024);
  }

  // ============== AccessLogOverride Deserialization Tests ==============

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
    // Unspecified fields should be None
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
