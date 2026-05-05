//! Access log plugin configuration.

use serde::Deserialize;

/// Configuration for the access_log.file layer.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AccessLogConfig {
  /// Context fields to include in log entries.
  /// Empty vector means no extension fields are logged.
  pub context_fields: Vec<String>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_default_config() {
    let config = AccessLogConfig::default();
    assert!(config.context_fields.is_empty());
  }

  #[test]
  fn test_deserialize_config() {
    let yaml = r#"
context_fields:
  - auth.basic_auth.user
  - connect_tcp.connect_tcp.connect_ms
"#;
    let config: AccessLogConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.context_fields.len(), 2);
    assert_eq!(config.context_fields[0], "auth.basic_auth.user");
  }
}
