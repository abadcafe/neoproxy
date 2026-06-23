use std::collections::HashMap;

use crate::plugins::access_log::context::{AccessLogEntry, LogFormat};

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
    .insert("basic_auth.user".to_string(), "admin".to_string());
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Text,
  );
  let text = String::from_utf8(output).unwrap();
  assert!(text.contains("basic_auth.user=admin"));
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

#[test]
fn test_format_json_basic() {
  let entry = make_entry();
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Json,
  );
  let text = String::from_utf8(output).unwrap();
  assert!(text.ends_with('\n'));
  let parsed: serde_json::Value =
    serde_json::from_str(text.trim()).unwrap();
  assert_eq!(parsed["status"], 200);
  assert_eq!(parsed["method"], "GET");
  assert_eq!(parsed["target"], "http://example.com/");
}

#[test]
fn test_format_json_with_extensions() {
  let mut entry = make_entry();
  entry.extensions.insert("user".to_string(), "admin".to_string());
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Json,
  );
  let text = String::from_utf8(output).unwrap();
  let parsed: serde_json::Value =
    serde_json::from_str(text.trim()).unwrap();
  // CR-001 fix: extensions are nested under "extensions" key
  assert_eq!(parsed["extensions"]["user"], "admin");
}

#[test]
fn test_format_json_extensions_are_sorted() {
  // Run 100 times with different HashMap states to catch
  // non-determinism. If extensions are not sorted, at least one
  // run will produce a different key order.
  let mut all_ext_keys: Vec<Vec<String>> = Vec::new();
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
      LogFormat::Json,
    );
    let text = String::from_utf8(output).unwrap();
    let parsed: serde_json::Value =
      serde_json::from_str(text.trim()).unwrap();
    // CR-001 fix: extensions are nested under "extensions" key
    let ext_obj = parsed["extensions"].as_object().unwrap();
    let ext_keys: Vec<String> = ext_obj
      .keys()
      .filter(|k| k.starts_with("key_"))
      .cloned()
      .collect();
    all_ext_keys.push(ext_keys);
  }
  // All iterations should produce the same sorted key order
  let first = &all_ext_keys[0];
  for (i, keys) in all_ext_keys.iter().enumerate() {
    assert_eq!(first, keys, "Key order differs on iteration {}", i);
  }
  // And should be sorted alphabetically
  assert_eq!(
    first,
    &vec![
      "key_a".to_string(),
      "key_b".to_string(),
      "key_c".to_string(),
      "key_d".to_string(),
      "key_e".to_string(),
    ],
    "JSON extension keys should be sorted alphabetically"
  );
}

#[test]
fn test_format_json_with_error() {
  let mut entry = make_entry();
  entry.status = 500;
  entry.err = Some("connection refused".to_string());
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Json,
  );
  let text = String::from_utf8(output).unwrap();
  let parsed: serde_json::Value =
    serde_json::from_str(text.trim()).unwrap();
  assert_eq!(parsed["status"], 500);
  assert_eq!(parsed["error"], "connection refused");
}

#[test]
fn test_format_json_extensions_under_dedicated_key() {
  // CR-001: Extension keys must be placed under a dedicated
  // "extensions" object in JSON format, not inserted at the top
  // level alongside built-in keys. This prevents extension keys
  // from silently overwriting built-in keys (e.g., a context
  // field producing a key that matches "status" would overwrite
  // the HTTP status code).
  let mut entry = make_entry();
  entry.extensions.insert("user".to_string(), "admin".to_string());
  entry.extensions.insert("role".to_string(), "superuser".to_string());
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Json,
  );
  let text = String::from_utf8(output).unwrap();
  let parsed: serde_json::Value =
    serde_json::from_str(text.trim()).unwrap();

  // Built-in keys must remain at the top level
  assert_eq!(
    parsed["status"], 200,
    "Built-in 'status' must not be overwritten"
  );
  assert_eq!(
    parsed["method"], "GET",
    "Built-in 'method' must not be overwritten"
  );

  // Extensions must be under the "extensions" key
  let ext = parsed
    .get("extensions")
    .expect("JSON should have 'extensions' key");
  assert_eq!(
    ext["user"], "admin",
    "Extension 'user' should be under 'extensions'"
  );
  assert_eq!(
    ext["role"], "superuser",
    "Extension 'role' should be under 'extensions'"
  );

  // Extension keys must NOT be at the top level
  assert!(
    parsed.get("user").is_none(),
    "Extension 'user' must not be at top level"
  );
  assert!(
    parsed.get("role").is_none(),
    "Extension 'role' must not be at top level"
  );
}

#[test]
fn test_format_json_extension_key_collides_with_builtin() {
  // CR-001: Even if an extension key matches a built-in key name
  // (e.g., "status"), it must not overwrite the built-in value.
  // The extension goes under "extensions" while the built-in
  // stays at the top level.
  let mut entry = make_entry();
  entry.extensions.insert("status".to_string(), "ok".to_string());
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Json,
  );
  let text = String::from_utf8(output).unwrap();
  let parsed: serde_json::Value =
    serde_json::from_str(text.trim()).unwrap();

  // Built-in "status" must remain the HTTP status code (200)
  assert_eq!(
    parsed["status"], 200,
    "Built-in 'status' must not be overwritten by extension"
  );

  // Extension "status" must be under "extensions"
  let ext = parsed
    .get("extensions")
    .expect("JSON should have 'extensions' key");
  assert_eq!(
    ext["status"], "ok",
    "Extension 'status' should be under 'extensions'"
  );
}

#[test]
fn test_format_json_no_extensions_no_extensions_key() {
  // CR-001: When there are no extensions, the "extensions" key should
  // not appear in the JSON output.
  let entry = make_entry();
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Json,
  );
  let text = String::from_utf8(output).unwrap();
  let parsed: serde_json::Value =
    serde_json::from_str(text.trim()).unwrap();
  assert!(
    parsed.get("extensions").is_none(),
    "No 'extensions' key when no extensions"
  );
}

#[test]
fn test_format_text_extensions_at_top_level() {
  // CR-001: For text format, extensions remain at the top level as
  // key=value pairs (visually distinguishable). This test verifies
  // text format is NOT changed by the JSON fix.
  let mut entry = make_entry();
  entry.extensions.insert("user".to_string(), "admin".to_string());
  let output = crate::plugins::access_log::formatter::format_entry(
    &entry,
    LogFormat::Text,
  );
  let text = String::from_utf8(output).unwrap();
  assert!(
    text.contains("user=admin"),
    "Text format should have extension at top level"
  );
}
