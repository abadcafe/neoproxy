use std::collections::HashMap;

use time::OffsetDateTime;

use super::context::{AccessLogEntry, LogFormat};

#[test]
fn test_log_format_deserializes_lowercase_variants() {
  let text: LogFormat = serde_yaml::from_str("text").unwrap();
  let json: LogFormat = serde_yaml::from_str("json").unwrap();

  assert_eq!(text, LogFormat::Text);
  assert_eq!(json, LogFormat::Json);
}

#[test]
fn test_access_log_entry_preserves_request_context_fields() {
  let mut extensions = HashMap::new();
  extensions.insert("trace_id".to_string(), "abc".to_string());
  let entry = AccessLogEntry {
    time: OffsetDateTime::UNIX_EPOCH,
    client_ip: "127.0.0.1".to_string(),
    client_port: 1234,
    server_ip: "127.0.0.1".to_string(),
    server_port: 8080,
    method: "GET".to_string(),
    target: "/health".to_string(),
    status: 200,
    duration_ms: 7,
    service: "api".to_string(),
    err: None,
    extensions,
  };

  assert_eq!(entry.method, "GET");
  assert_eq!(entry.target, "/health");
  assert_eq!(entry.extensions["trace_id"], "abc");
}
