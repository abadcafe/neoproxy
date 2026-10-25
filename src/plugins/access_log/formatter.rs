//! Access log entry formatting.

use serde_json::json;

use super::context::{AccessLogEntry, LogFormat};

/// Format an access log entry.
pub(crate) fn format_entry(
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
  let mut buf = String::with_capacity(256);

  let format_desc = time::macros::format_description!(
    "[year]-[month]-[day] [hour]:[minute]:[second]"
  );
  let time_str = entry
    .time
    .format(format_desc)
    .unwrap_or_else(|_| "???".to_string());

  let _ = write!(
    buf,
    "[{}] {}:{} -> {}:{} {} {} {} {}ms",
    time_str,
    escape(&entry.client_ip),
    entry.client_port,
    escape(&entry.server_ip),
    entry.server_port,
    escape(&entry.method),
    escape(&entry.target),
    entry.status,
    entry.duration_ms,
  );

  if !entry.service.is_empty() {
    let _ = write!(buf, " svc={}", escape(&entry.service));
  }

  if let Some(err) = &entry.err {
    let _ = write!(buf, " err={}", escape(err));
  }

  let mut sorted_exts: Vec<_> = entry.extensions.iter().collect();
  sorted_exts.sort_by_key(|(key, _)| *key);
  for (key, value) in &sorted_exts {
    let _ = write!(buf, " {}={}", escape(key), escape(value));
  }

  buf.push('\n');
  buf.into_bytes()
}

fn format_json(entry: &AccessLogEntry) -> Vec<u8> {
  use time::format_description::well_known::Iso8601;
  let time_str = entry
    .time
    .format(&Iso8601::DEFAULT)
    .unwrap_or_else(|_| "???".to_string());

  let mut obj = serde_json::Map::new();
  obj.insert("time".to_string(), json!(time_str));
  obj.insert(
    "client".to_string(),
    json!(format!("{}:{}", entry.client_ip, entry.client_port)),
  );
  obj.insert(
    "server".to_string(),
    json!(format!("{}:{}", entry.server_ip, entry.server_port)),
  );
  obj.insert("method".to_string(), json!(entry.method));
  obj.insert("target".to_string(), json!(entry.target));
  obj.insert("status".to_string(), json!(entry.status));
  obj.insert("duration_ms".to_string(), json!(entry.duration_ms));

  if !entry.service.is_empty() {
    obj.insert("service".to_string(), json!(entry.service));
  }

  if let Some(err) = &entry.err {
    obj.insert("error".to_string(), json!(err));
  }

  // CR-001 fix: Place extensions under a dedicated "extensions" key
  // instead of inserting them at the top level. This prevents extension
  // keys from silently overwriting built-in keys (e.g., a context field
  // producing a display_key that matches "status" would overwrite the
  // HTTP status code with an arbitrary string).
  if !entry.extensions.is_empty() {
    let mut ext_obj = serde_json::Map::new();
    let mut sorted_exts: Vec<_> = entry.extensions.iter().collect();
    sorted_exts.sort_by_key(|(key, _)| *key);
    for (key, value) in sorted_exts {
      ext_obj.insert(key.clone(), json!(value));
    }
    obj.insert(
      "extensions".to_string(),
      serde_json::Value::Object(ext_obj),
    );
  }

  let mut bytes =
    serde_json::to_string(&obj).unwrap_or_default().into_bytes();
  bytes.push(b'\n');
  bytes
}

fn escape(value: &str) -> String {
  value.chars().flat_map(char::escape_debug).collect()
}
