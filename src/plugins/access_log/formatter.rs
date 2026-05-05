//! Access log entry formatting.

use super::context::{AccessLogEntry, LogFormat};

/// Format an access log entry.
pub fn format_entry(
  entry: &AccessLogEntry,
  format: LogFormat,
) -> Vec<u8> {
  match format {
    LogFormat::Text => format_text(entry),
  }
}

fn format_text(entry: &AccessLogEntry) -> Vec<u8> {
  use std::fmt::Write;
  let mut buf = String::with_capacity(256);

  let format_desc = time::format_description::parse(
    "[year]-[month]-[day] [hour]:[minute]:[second]",
  )
  .unwrap_or_default();
  let time_str = entry
    .time
    .format(&format_desc)
    .unwrap_or_else(|_| "???".to_string());

  let _ = write!(
    buf,
    "[{}] {}:{} -> {}:{} {} {} {} {}ms",
    time_str,
    entry.client_ip,
    entry.client_port,
    entry.server_ip,
    entry.server_port,
    entry.method,
    entry.target,
    entry.status,
    entry.duration_ms,
  );

  if !entry.service.is_empty() {
    let _ = write!(buf, " svc={}", entry.service);
  }

  if let Some(err) = &entry.err {
    let _ = write!(buf, " err={}", err);
  }

  let mut sorted_exts: Vec<_> = entry.extensions.iter().collect();
  sorted_exts.sort_by_key(|(k, _)| (*k).clone());
  for (key, value) in &sorted_exts {
    let _ = write!(buf, " {}={}", key, value);
  }

  buf.push('\n');
  buf.into_bytes()
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use crate::plugins::access_log::context::{
    AccessLogEntry, LogFormat,
  };

  fn make_entry() -> AccessLogEntry {
    AccessLogEntry {
      time: time::OffsetDateTime::now_utc(),
      client_ip: "127.0.0.1".to_string(),
      client_port: 12345,
      server_ip: "0.0.0.0".to_string(),
      server_port: 8080,
      method: "GET".to_string(),
      target: "http://example.com/".to_string(),
      status: 200,
      duration_ms: 42,
      service: "echo".to_string(),
      err: None,
      extensions: HashMap::new(),
    }
  }

  #[test]
  fn test_format_text_basic() {
    let entry = make_entry();
    let output = crate::plugins::access_log::formatter::format_entry(
      &entry,
      LogFormat::Text,
    );
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("127.0.0.1"));
    assert!(text.contains("200"));
    assert!(text.contains("42ms"));
    assert!(text.ends_with('\n'));
  }

  #[test]
  fn test_format_text_with_extensions() {
    let mut entry = make_entry();
    entry
      .extensions
      .insert("auth.basic_auth.user".to_string(), "admin".to_string());
    let output = crate::plugins::access_log::formatter::format_entry(
      &entry,
      LogFormat::Text,
    );
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("auth.basic_auth.user=admin"));
  }

  #[test]
  fn test_format_text_extensions_are_sorted() {
    // Run 100 times with different HashMap states to catch
    // non-determinism. If extensions are not sorted, at least one
    // run will produce a different output order.
    let mut outputs: Vec<String> = Vec::new();
    for _ in 0..100 {
      let mut entry = make_entry();
      // Use keys whose hash order differs from alphabetical order
      entry.extensions.insert("key_c".to_string(), "3".to_string());
      entry.extensions.insert("key_a".to_string(), "1".to_string());
      entry.extensions.insert("key_b".to_string(), "2".to_string());
      entry.extensions.insert("key_e".to_string(), "5".to_string());
      entry.extensions.insert("key_d".to_string(), "4".to_string());

      let output = crate::plugins::access_log::formatter::format_entry(
        &entry,
        LogFormat::Text,
      );
      let text = String::from_utf8(output).unwrap();
      // Extract only the extension part (after "echo\n" or svc= part)
      let ext_part =
        text.split("svc=").last().unwrap_or(&text).to_string();
      outputs.push(ext_part);
    }
    // All outputs should be identical (deterministic)
    let first = &outputs[0];
    for (i, output) in outputs.iter().enumerate() {
      assert_eq!(first, output, "Output differs on iteration {}", i);
    }
    // And should be sorted
    assert!(
      first.contains("key_a=1 key_b=2 key_c=3 key_d=4 key_e=5"),
      "Extensions should be sorted alphabetically, got: {}",
      first
    );
  }
}
