use std::fs;
use std::time::Duration;

use byte_unit::Byte;

use super::config::AccessLogWriterConfig;
use super::context::{AccessLogEntry, LogFormat};
use super::writer::AccessLogWriter;

fn make_entry(status: u16) -> AccessLogEntry {
  AccessLogEntry {
    time: time::OffsetDateTime::now_utc(),
    client_ip: "127.0.0.1".to_string(),
    client_port: 12345,
    server_ip: "0.0.0.0".to_string(),
    server_port: 8080,
    method: "GET".to_string(),
    target: "http://example.com/".to_string(),
    status,
    err: None,
    duration_ms: 42,
    service: "echo".to_string(),
    extensions: Default::default(),
  }
}

fn writer_config(
  dir: &tempfile::TempDir,
  name: &str,
  format: LogFormat,
) -> AccessLogWriterConfig {
  AccessLogWriterConfig {
    path_prefix: dir.path().join(name).to_string_lossy().to_string(),
    format,
    rotate_daily: false,
    ..AccessLogWriterConfig::default()
  }
}

#[test]
fn test_flush_empty_buffer_creates_no_file() {
  let dir = tempfile::tempdir().unwrap();
  let config = writer_config(&dir, "access.log", LogFormat::Text);
  let mut writer = AccessLogWriter::from_config(&config);

  writer.flush();

  assert!(!dir.path().join("access.log").exists());
}

#[test]
fn test_write_flush_writes_text_log() {
  let dir = tempfile::tempdir().unwrap();
  let config = writer_config(&dir, "access.log", LogFormat::Text);
  let mut writer = AccessLogWriter::from_config(&config);

  writer.write(&make_entry(200));
  writer.flush();

  let content =
    fs::read_to_string(dir.path().join("access.log")).unwrap();
  assert!(content.contains("GET"));
  assert!(content.contains("200"));
  assert!(content.contains("echo"));
}

#[test]
fn test_write_flush_writes_json_log() {
  let dir = tempfile::tempdir().unwrap();
  let config = writer_config(&dir, "access.json", LogFormat::Json);
  let mut writer = AccessLogWriter::from_config(&config);

  writer.write(&make_entry(502));
  writer.flush();

  let content =
    fs::read_to_string(dir.path().join("access.json")).unwrap();
  let value: serde_json::Value =
    serde_json::from_str(content.trim()).unwrap();
  assert_eq!(value["method"], "GET");
  assert_eq!(value["status"], 502);
  assert_eq!(value["service"], "echo");
}

#[test]
fn test_multiple_writes_flush_as_multiple_lines() {
  let dir = tempfile::tempdir().unwrap();
  let config = writer_config(&dir, "access.log", LogFormat::Text);
  let mut writer = AccessLogWriter::from_config(&config);

  writer.write(&make_entry(200));
  writer.write(&make_entry(404));
  writer.flush();

  let content =
    fs::read_to_string(dir.path().join("access.log")).unwrap();
  let lines: Vec<_> = content.lines().collect();
  assert_eq!(lines.len(), 2);
  assert!(lines[0].contains("200"));
  assert!(lines[1].contains("404"));
}

#[test]
fn test_flush_if_interval_elapsed_does_not_flush_before_interval() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    flush_interval: Duration::from_secs(3600),
    ..writer_config(&dir, "access.log", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::from_config(&config);

  writer.write(&make_entry(200));
  writer.flush_if_interval_elapsed();

  assert!(!dir.path().join("access.log").exists());
}

#[test]
fn test_flush_if_interval_elapsed_flushes_after_interval() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    flush_interval: Duration::from_millis(1),
    ..writer_config(&dir, "access.log", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::from_config(&config);

  writer.write(&make_entry(200));
  std::thread::sleep(Duration::from_millis(5));
  writer.flush_if_interval_elapsed();

  let content =
    fs::read_to_string(dir.path().join("access.log")).unwrap();
  assert!(content.contains("200"));
}

#[test]
fn test_rotate_daily_true_uses_date_suffix() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    rotate_daily: true,
    ..writer_config(&dir, "access", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::from_config(&config);

  writer.write(&make_entry(200));
  writer.flush();

  let files: Vec<_> = fs::read_dir(dir.path())
    .unwrap()
    .map(|entry| {
      entry.unwrap().file_name().to_string_lossy().to_string()
    })
    .collect();
  assert_eq!(files.len(), 1);
  assert!(files[0].starts_with("access."));
}

#[test]
fn test_buffer_size_limit_drops_oversized_entry() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    max_buffer_size: Byte::from_u64(1),
    ..writer_config(&dir, "access.log", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::from_config(&config);

  writer.write(&make_entry(200));
  writer.flush();

  assert!(!dir.path().join("access.log").exists());
}
