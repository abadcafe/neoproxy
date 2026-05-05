//! Access log entry types.

use std::collections::HashMap;

use time::OffsetDateTime;

/// A complete access log entry ready for formatting.
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
  pub time: OffsetDateTime,
  pub client_ip: String,
  pub client_port: u16,
  pub server_ip: String,
  pub server_port: u16,
  pub method: String,
  pub target: String,
  pub status: u16,
  pub duration_ms: u64,
  pub service: String,
  pub err: Option<String>,
  pub extensions: HashMap<String, String>,
}

/// Log format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
  #[default]
  Text,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_access_log_entry_creation() {
    let entry = crate::plugins::access_log::context::AccessLogEntry {
      time: OffsetDateTime::now_utc(),
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      server_ip: "10.0.0.1".to_string(),
      server_port: 8080,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      err: None,
      extensions: HashMap::new(),
    };
    assert_eq!(entry.client_ip, "192.168.1.1");
    assert_eq!(entry.status, 200);
    assert!(entry.extensions.is_empty());
  }

  #[test]
  fn test_access_log_entry_with_extensions() {
    let mut extensions = HashMap::new();
    extensions
      .insert("auth.basic_auth.user".to_string(), "admin".to_string());
    let entry = crate::plugins::access_log::context::AccessLogEntry {
      time: OffsetDateTime::now_utc(),
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      server_ip: "10.0.0.1".to_string(),
      server_port: 8080,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      err: None,
      extensions,
    };
    assert_eq!(
      entry.extensions.get("auth.basic_auth.user"),
      Some(&"admin".to_string())
    );
  }

  #[test]
  fn test_log_format_default() {
    assert_eq!(
      crate::plugins::access_log::context::LogFormat::default(),
      crate::plugins::access_log::context::LogFormat::Text
    );
  }
}
