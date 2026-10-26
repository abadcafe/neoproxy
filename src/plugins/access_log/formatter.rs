//! module: plugins::access_log::formatter
//! responsibility: serialize escaped access log records
//! public operations: format_entry
//! data entities: JsonRecord, JsonExtensions
//! tests: formatter_tests.rs

//! Access log entry formatting.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

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
    "[{}] {} -> {} {} {} {} {}ms",
    time_str,
    endpoint(&entry.client_ip, entry.client_port),
    endpoint(&entry.server_ip, entry.server_port),
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
    let _ =
      write!(buf, " {}={}", escape(key), escape(&value.to_string()));
  }

  buf.push('\n');
  buf.into_bytes()
}

struct JsonRecord<'a>(&'a AccessLogEntry);
struct JsonExtensions<'a>(
  &'a std::collections::HashMap<
    String,
    crate::context::value::ContextValue,
  >,
);

impl Serialize for JsonRecord<'_> {
  fn serialize<S: Serializer>(
    &self,
    serializer: S,
  ) -> Result<S::Ok, S::Error> {
    use time::format_description::well_known::Iso8601;
    let entry = self.0;
    let mut output = serializer.serialize_map(None)?;
    // Keep the established deterministic field order while serializing
    // native values directly, without an intermediate JSON value tree.
    output.serialize_entry(
      "client",
      &endpoint(&entry.client_ip, entry.client_port),
    )?;
    output.serialize_entry("duration_ms", &entry.duration_ms)?;
    if let Some(error) = &entry.err {
      output.serialize_entry("error", error)?;
    }
    if !entry.extensions.is_empty() {
      output.serialize_entry(
        "extensions",
        &JsonExtensions(&entry.extensions),
      )?;
    }
    output.serialize_entry("method", &entry.method)?;
    output.serialize_entry(
      "server",
      &endpoint(&entry.server_ip, entry.server_port),
    )?;
    if !entry.service.is_empty() {
      output.serialize_entry("service", &entry.service)?;
    }
    output.serialize_entry("status", &entry.status)?;
    output.serialize_entry("target", &entry.target)?;
    output.serialize_entry(
      "time",
      &entry
        .time
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "???".into()),
    )?;
    output.end()
  }
}
impl Serialize for JsonExtensions<'_> {
  fn serialize<S: Serializer>(
    &self,
    serializer: S,
  ) -> Result<S::Ok, S::Error> {
    let mut fields: Vec<_> = self.0.iter().collect();
    fields.sort_by_key(|(key, _)| *key);
    serializer.collect_map(fields)
  }
}
fn format_json(entry: &AccessLogEntry) -> Vec<u8> {
  let mut bytes = serde_json::to_vec(&JsonRecord(entry))
    .expect("native access records must serialize to JSON");
  bytes.push(b'\n');
  bytes
}

fn escape(value: &str) -> String {
  value.chars().flat_map(char::escape_debug).collect()
}

fn endpoint(ip: &str, port: u16) -> String {
  let ip = escape(ip);
  if ip.contains(':') {
    format!("[{ip}]:{port}")
  } else {
    format!("{ip}:{port}")
  }
}
