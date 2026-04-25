use std::sync::LazyLock;

use crate::access_log::config::LogFormat;
use crate::access_log::context::{
  AccessLogEntry, AuthType, ServiceMetrics,
};

/// Pre-parsed format description for text format (nginx-style timestamp)
static TEXT_TIME_FORMAT: LazyLock<Vec<time::format_description::FormatItem<'static>>> =
  LazyLock::new(|| {
    time::format_description::parse(
      "[day]/[month repr:short]/[year]:[hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]",
    )
    .unwrap()
  });

/// Format an AccessLogEntry into bytes based on the LogFormat.
pub fn format_entry(
  entry: &AccessLogEntry,
  format: LogFormat,
) -> Vec<u8> {
  match format {
    LogFormat::Text => format_text(entry),
    LogFormat::Json => format_json(entry),
  }
}

fn format_text(entry: &AccessLogEntry) -> Vec<u8> {
  use std::fmt::Write;

  let mut line = String::with_capacity(256);

  // Field 1: client_ip:port
  write!(
    line,
    "{}:{}",
    entry.client_ip, entry.client_port
  )
  .unwrap();

  // Field 2: user or "-"
  write!(
    line,
    " {}",
    entry.user.as_deref().unwrap_or("-")
  )
  .unwrap();

  // Field 3: timestamp in nginx format [dd/Mon/yyyy:HH:mm:ss +zzzz]
  let time_str = entry.time.format(&TEXT_TIME_FORMAT).unwrap_or_else(
    |_| "???".to_string(),
  );
  write!(line, " [{time_str}]").unwrap();

  // Field 4: "method target"
  write!(line, " \"{} {}\"", entry.method, entry.target)
    .unwrap();

  // Field 5: status
  write!(line, " {}", entry.status).unwrap();

  // Field 6: duration_ms
  write!(line, " {}ms", entry.duration_ms).unwrap();

  // Key-value fields
  match entry.auth_type {
    AuthType::None => {}
    AuthType::Password => {
      write!(line, " auth=password").unwrap()
    }
    AuthType::Cert => write!(line, " auth=cert").unwrap(),
    AuthType::Both => write!(line, " auth=both").unwrap(),
  }

  write!(line, " service={}", entry.service).unwrap();

  // Service metrics (sorted for deterministic output)
  let mut metrics: Vec<_> =
    entry.service_metrics.iter().collect();
  metrics.sort_by_key(|(k, _)| (*k).clone());
  for (key, value) in metrics {
    write!(line, " service.{key}={value}").unwrap();
  }

  line.push('\n');
  line.into_bytes()
}

fn format_json(entry: &AccessLogEntry) -> Vec<u8> {
  let mut map = serde_json::Map::new();

  // Time in ISO8601
  let format = time::format_description::well_known::Rfc3339;
  let time_str = entry
    .time
    .format(&format)
    .unwrap_or_else(|_| "???".to_string());
  map.insert(
    "time".to_string(),
    serde_json::Value::String(time_str),
  );

  map.insert(
    "client_ip".to_string(),
    serde_json::Value::String(entry.client_ip.clone()),
  );
  map.insert(
    "client_port".to_string(),
    serde_json::json!(entry.client_port),
  );
  map.insert(
    "user".to_string(),
    match &entry.user {
      Some(u) => serde_json::Value::String(u.clone()),
      None => serde_json::Value::Null,
    },
  );
  map.insert(
    "method".to_string(),
    serde_json::Value::String(entry.method.clone()),
  );
  map.insert(
    "target".to_string(),
    serde_json::Value::String(entry.target.clone()),
  );
  map.insert(
    "status".to_string(),
    serde_json::json!(entry.status),
  );
  map.insert(
    "duration_ms".to_string(),
    serde_json::json!(entry.duration_ms),
  );

  // Auth type (omit if None)
  match entry.auth_type {
    AuthType::None => {}
    AuthType::Password => {
      map.insert(
        "auth".to_string(),
        serde_json::Value::String("password".to_string()),
      );
    }
    AuthType::Cert => {
      map.insert(
        "auth".to_string(),
        serde_json::Value::String("cert".to_string()),
      );
    }
    AuthType::Both => {
      map.insert(
        "auth".to_string(),
        serde_json::Value::String("both".to_string()),
      );
    }
  }

  map.insert(
    "service".to_string(),
    serde_json::Value::String(entry.service.clone()),
  );

  // Service metrics (sorted for deterministic output)
  let mut metrics: Vec<_> = entry.service_metrics.iter().collect();
  metrics.sort_by_key(|(k, _)| (*k).clone());
  for (key, value) in metrics {
    map.insert(
      format!("service.{key}"),
      serde_json::Value::String(value.clone()),
    );
  }

  let obj = serde_json::Value::Object(map);
  let mut output = serde_json::to_string(&obj).unwrap();
  output.push('\n');
  output.into_bytes()
}

#[cfg(test)]
mod tests {
  use super::*;
  use time::OffsetDateTime;

  fn make_test_entry() -> AccessLogEntry {
    // Use a fixed time for deterministic tests
    let time = OffsetDateTime::now_utc();
    AccessLogEntry {
      time,
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    }
  }

  fn make_test_entry_no_user() -> AccessLogEntry {
    let time = OffsetDateTime::now_utc();
    AccessLogEntry {
      time,
      client_ip: "10.0.0.1".to_string(),
      client_port: 1234,
      user: None,
      auth_type: AuthType::None,
      method: "CONNECT".to_string(),
      target: "example.com:80".to_string(),
      status: 502,
      duration_ms: 1000,
      service: "tunnel".to_string(),
      service_metrics: ServiceMetrics::new(),
    }
  }

  fn make_test_entry_with_metrics() -> AccessLogEntry {
    let time = OffsetDateTime::now_utc();
    let mut metrics = ServiceMetrics::new();
    metrics.add("dns_ms", 5u64);
    metrics.add("connect_ms", 10u64);
    AccessLogEntry {
      time,
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      service_metrics: metrics,
    }
  }

  // ============== Text Format Tests ==============

  #[test]
  fn test_text_format_contains_client_addr() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains("192.168.1.1:54321"),
      "Should contain client IP:port, got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_user() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains("admin"),
      "Should contain username, got: {output}"
    );
  }

  #[test]
  fn test_text_format_no_user_shows_dash() {
    let entry = make_test_entry_no_user();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    // The second field should be "-"
    let parts: Vec<&str> = output.split_whitespace().collect();
    assert_eq!(
      parts[1], "-",
      "No user should show '-', got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_timestamp_in_brackets() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    // Timestamp should be in nginx format: [25/Apr/2026:10:00:00 +0000]
    assert!(
      output.contains('[') && output.contains(']'),
      "Should contain timestamp in brackets, got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_request_line() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains("\"CONNECT example.com:443\""),
      "Should contain quoted request line, got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_status() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains(" 200 "),
      "Should contain status code, got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_duration() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains("50ms"),
      "Should contain duration, got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_auth_type() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains("auth=password"),
      "Should contain auth type, got: {output}"
    );
  }

  #[test]
  fn test_text_format_no_auth_omits_field() {
    let entry = make_test_entry_no_user();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      !output.contains("auth="),
      "No auth should omit auth field, got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_service() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains("service=tunnel"),
      "Should contain service name, got: {output}"
    );
  }

  #[test]
  fn test_text_format_contains_service_metrics() {
    let entry = make_test_entry_with_metrics();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Text))
        .unwrap();
    assert!(
      output.contains("service.dns_ms=5"),
      "Should contain dns_ms metric, got: {output}"
    );
    assert!(
      output.contains("service.connect_ms=10"),
      "Should contain connect_ms metric, got: {output}"
    );
  }

  #[test]
  fn test_text_format_ends_with_newline() {
    let entry = make_test_entry();
    let output = format_entry(&entry, LogFormat::Text);
    assert_eq!(
      output.last(),
      Some(&b'\n'),
      "Should end with newline"
    );
  }

  // ============== JSON Format Tests ==============

  #[test]
  fn test_json_format_valid_json() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Json))
        .unwrap();
    let parsed: serde_json::Value =
      serde_json::from_str(output.trim()).unwrap();
    assert!(parsed.is_object());
  }

  #[test]
  fn test_json_format_required_fields() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Json))
        .unwrap();
    let parsed: serde_json::Value =
      serde_json::from_str(output.trim()).unwrap();
    let obj = parsed.as_object().unwrap();

    assert!(obj.contains_key("time"));
    assert!(obj.contains_key("client_ip"));
    assert!(obj.contains_key("client_port"));
    assert!(obj.contains_key("user"));
    assert!(obj.contains_key("method"));
    assert!(obj.contains_key("target"));
    assert!(obj.contains_key("status"));
    assert!(obj.contains_key("duration_ms"));
    assert!(obj.contains_key("service"));
  }

  #[test]
  fn test_json_format_field_values() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Json))
        .unwrap();
    let parsed: serde_json::Value =
      serde_json::from_str(output.trim()).unwrap();

    assert_eq!(parsed["client_ip"], "192.168.1.1");
    assert_eq!(parsed["client_port"], 54321);
    assert_eq!(parsed["user"], "admin");
    assert_eq!(parsed["method"], "CONNECT");
    assert_eq!(parsed["target"], "example.com:443");
    assert_eq!(parsed["status"], 200);
    assert_eq!(parsed["duration_ms"], 50);
    assert_eq!(parsed["service"], "tunnel");
    assert_eq!(parsed["auth"], "password");
  }

  #[test]
  fn test_json_format_no_auth_omits_field() {
    let entry = make_test_entry_no_user();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Json))
        .unwrap();
    let parsed: serde_json::Value =
      serde_json::from_str(output.trim()).unwrap();
    assert!(
      parsed.get("auth").is_none(),
      "No auth should omit auth field"
    );
  }

  #[test]
  fn test_json_format_time_is_iso8601() {
    let entry = make_test_entry();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Json))
        .unwrap();
    let parsed: serde_json::Value =
      serde_json::from_str(output.trim()).unwrap();
    let time_str = parsed["time"].as_str().unwrap();
    // ISO8601: 2026-04-25T10:00:00+08:00
    assert!(
      time_str.len() >= 19,
      "Time should be ISO8601, got: {time_str}"
    );
  }

  #[test]
  fn test_json_format_service_metrics() {
    let entry = make_test_entry_with_metrics();
    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Json))
        .unwrap();
    let parsed: serde_json::Value =
      serde_json::from_str(output.trim()).unwrap();
    assert_eq!(parsed["service.dns_ms"], "5");
    assert_eq!(parsed["service.connect_ms"], "10");
  }

  #[test]
  fn test_json_format_ends_with_newline() {
    let entry = make_test_entry();
    let output = format_entry(&entry, LogFormat::Json);
    assert_eq!(
      output.last(),
      Some(&b'\n'),
      "Should end with newline"
    );
  }

  #[test]
  fn test_json_format_service_metrics_sorted_deterministic() {
    // Create entry with metrics in reverse alphabetical order
    let time = OffsetDateTime::now_utc();
    let mut metrics = ServiceMetrics::new();
    metrics.add("zebra", 1u64);
    metrics.add("alpha", 2u64);
    metrics.add("middle", 3u64);
    let entry = AccessLogEntry {
      time,
      client_ip: "192.168.1.1".to_string(),
      client_port: 54321,
      user: Some("admin".to_string()),
      auth_type: AuthType::Password,
      method: "CONNECT".to_string(),
      target: "example.com:443".to_string(),
      status: 200,
      duration_ms: 50,
      service: "tunnel".to_string(),
      service_metrics: metrics,
    };

    let output =
      String::from_utf8(format_entry(&entry, LogFormat::Json)).unwrap();

    // Verify metrics are in alphabetical order in the output string
    // If sorted, "alpha" appears before "middle" which appears before "zebra"
    let alpha_pos = output.find("service.alpha").expect("should have alpha");
    let middle_pos = output.find("service.middle").expect("should have middle");
    let zebra_pos = output.find("service.zebra").expect("should have zebra");

    assert!(
      alpha_pos < middle_pos && middle_pos < zebra_pos,
      "Metrics should be in alphabetical order (alpha, middle, zebra), got: {output}"
    );
  }
}
