use std::cell::Cell;
use std::fs;
use std::rc::Rc;

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
fn test_write_below_capacity_remains_buffered_until_flush() {
  let directory = tempfile::tempdir().unwrap();
  let config = writer_config(&directory, "access.log", LogFormat::Text);
  let mut writer = AccessLogWriter::from_config(&config);
  writer.write(&make_entry(200));
  assert!(!directory.path().join("access.log").exists());
  writer.flush();
  assert!(
    fs::read_to_string(directory.path().join("access.log"))
      .unwrap()
      .contains("200")
  );
}

#[test]
fn test_write_reaching_capacity_flushes_without_explicit_flush() {
  let directory = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    buffer_capacity: Byte::from_u64(1),
    ..writer_config(&directory, "access.log", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::from_config(&config);
  writer.write(&make_entry(201));
  assert!(
    fs::read_to_string(directory.path().join("access.log"))
      .unwrap()
      .contains("201")
  );
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

#[test]
fn test_write_rotates_full_file_and_preserves_entries() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    max_file_size: Byte::from_u64(1),
    ..writer_config(&dir, "access.log", LogFormat::Text)
  };
  for status in [200, 201, 202] {
    // Reopening must account for bytes already on disk.
    let mut writer = AccessLogWriter::from_config(&config);
    writer.write(&make_entry(status));
    writer.flush();
  }
  let entries: Vec<_> = fs::read_dir(dir.path())
    .unwrap()
    .map(|path| fs::read_to_string(path.unwrap().path()).unwrap())
    .collect();
  assert_eq!(entries.len(), 3);
  for status in [200, 201, 202] {
    assert!(
      entries.iter().any(|text| text.contains(&status.to_string()))
    );
  }
}

#[test]
fn test_write_archive_numbers_advance_after_old_archive_is_removed() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    max_file_size: Byte::from_u64(1),
    ..writer_config(&dir, "access.log", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::from_config(&config);
  for status in [200, 201, 202] {
    writer.write(&make_entry(status));
    writer.flush();
  }
  fs::remove_file(dir.path().join("access.log.1")).unwrap();
  writer.write(&make_entry(203));
  writer.flush();
  assert!(!dir.path().join("access.log.1").exists());
  let archive =
    fs::read_to_string(dir.path().join("access.log.3")).unwrap();
  assert!(archive.contains("202"));
}

#[test]
fn test_write_skips_occupied_archive_number_without_overwriting() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    max_file_size: Byte::from_u64(1),
    ..writer_config(&dir, "access.log", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::from_config(&config);
  for status in [200, 201] {
    writer.write(&make_entry(status));
    writer.flush();
  }
  fs::write(dir.path().join("access.log.2"), "existing archive\n")
    .unwrap();
  writer.write(&make_entry(202));
  writer.flush();
  assert_eq!(
    fs::read_to_string(dir.path().join("access.log.2")).unwrap(),
    "existing archive\n"
  );
  assert!(
    fs::read_to_string(dir.path().join("access.log.3"))
      .unwrap()
      .contains("201")
  );
}

#[test]
fn test_flush_date_change_switches_file_and_resets_archive_sequence() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    max_file_size: Byte::from_u64(1),
    rotate_daily: true,
    ..writer_config(&dir, "access", LogFormat::Text)
  };
  let date = Rc::new(Cell::new(time::macros::date!(2026 - 10 - 25)));
  let source = date.clone();
  let mut writer =
    AccessLogWriter::with_date_source(&config, move || {
      Ok(source.get())
    });
  for status in [200, 201, 202] {
    writer.write(&make_entry(status));
    writer.flush();
  }
  let previous = dir.path().join("access.2026-10-25");
  let previous_content = fs::read(&previous).unwrap();
  date.set(time::macros::date!(2026 - 10 - 26));
  for status in [203, 204] {
    writer.write(&make_entry(status));
    writer.flush();
  }
  assert_eq!(fs::read(previous).unwrap(), previous_content);
  assert!(
    fs::read_to_string(dir.path().join("access.2026-10-26.1"))
      .unwrap()
      .contains("203")
  );
  assert!(
    fs::read_to_string(dir.path().join("access.2026-10-26"))
      .unwrap()
      .contains("204")
  );
  assert!(!dir.path().join("access.2026-10-26.3").exists());

  // Clock corrections can revisit a date. Existing archives still
  // belong to that date and must remain intact when its file reopens.
  date.set(time::macros::date!(2026 - 10 - 25));
  writer.write(&make_entry(205));
  writer.flush();
  assert_eq!(
    fs::read(dir.path().join("access.2026-10-25.3")).unwrap(),
    previous_content
  );
}

#[test]
fn test_flush_daily_rotation_does_not_fall_back_to_utc_on_date_error() {
  let dir = tempfile::tempdir().unwrap();
  let config = AccessLogWriterConfig {
    rotate_daily: true,
    ..writer_config(&dir, "access", LogFormat::Text)
  };
  let mut writer = AccessLogWriter::with_date_source(&config, || {
    Err(time::error::IndeterminateOffset)
  });
  writer.write(&make_entry(200));
  writer.flush();
  assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn test_flush_without_daily_rotation_does_not_require_local_date() {
  let dir = tempfile::tempdir().unwrap();
  let config = writer_config(&dir, "access.log", LogFormat::Text);
  let mut writer = AccessLogWriter::with_date_source(&config, || {
    Err(time::error::IndeterminateOffset)
  });
  writer.write(&make_entry(200));
  writer.flush();
  assert!(
    fs::read_to_string(dir.path().join("access.log"))
      .unwrap()
      .contains("200")
  );
}
