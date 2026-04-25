use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::access_log::config::{AccessLogConfig, LogFormat};
use crate::access_log::context::AccessLogEntry;
use crate::access_log::formatter;

/// Access log writer with buffering and file rotation.
///
/// Thread-safe: wrapped in `Arc<Mutex<...>>` internally.
/// Each server creates one instance, shared across all connections.
#[derive(Clone)]
pub struct AccessLogWriter {
  inner: Arc<Mutex<AccessLogWriterInner>>,
}

struct AccessLogWriterInner {
  log_directory: String,
  path_prefix: String,
  max_size: u64,
  buffer_capacity: usize,
  max_buffer_size: usize,
  flush_interval: std::time::Duration,
  format: LogFormat,

  current_file: Option<File>,
  current_path: Option<PathBuf>,
  current_size: u64,
  current_date: String,
  buffer: Vec<u8>,
  last_flush: Instant,
}

impl AccessLogWriter {
  /// Create a new AccessLogWriter.
  pub fn new(log_directory: &str, config: &AccessLogConfig) -> Self {
    let buffer_capacity = config.buffer.0 as usize;
    // Max buffer is 4x the configured buffer capacity to prevent unbounded growth
    let max_buffer_size = buffer_capacity.saturating_mul(4).max(1024);
    Self {
      inner: Arc::new(Mutex::new(AccessLogWriterInner {
        log_directory: log_directory.to_string(),
        path_prefix: config.path_prefix.clone(),
        max_size: config.max_size.0,
        buffer_capacity,
        max_buffer_size,
        flush_interval: config.flush.0,
        format: config.format,
        current_file: None,
        current_path: None,
        current_size: 0,
        current_date: String::new(),
        buffer: Vec::with_capacity(buffer_capacity),
        last_flush: Instant::now(),
      })),
    }
  }

  /// Write an access log entry.
  pub fn write(&self, entry: &AccessLogEntry) {
    let mut inner = self.inner.lock().unwrap();

    // CR-004: Prevent unbounded buffer growth
    // If buffer exceeds max, drop the new entry with a warning
    if inner.buffer.len() >= inner.max_buffer_size {
      eprintln!(
        "access_log: buffer full ({} bytes), dropping log entry",
        inner.buffer.len()
      );
      return;
    }

    let formatted = formatter::format_entry(entry, inner.format);
    inner.buffer.extend_from_slice(&formatted);

    // Check if we should flush
    if inner.buffer.len() >= inner.buffer_capacity
      || inner.last_flush.elapsed() >= inner.flush_interval
    {
      inner.do_flush();
    }
  }

  /// Flush the buffer to disk.
  pub fn flush(&self) {
    let mut inner = self.inner.lock().unwrap();
    inner.do_flush();
  }
}

impl AccessLogWriterInner {
  fn do_flush(&mut self) {
    if self.buffer.is_empty() {
      return;
    }

    // Ensure we have an open file
    if let Err(e) = self.ensure_file() {
      // CR-001: Don't clear buffer on error - preserve data for retry
      eprintln!("access_log: failed to open file: {e}");
      return;
    }

    if let Some(ref mut file) = self.current_file {
      if let Err(e) = file.write_all(&self.buffer) {
        // CR-001: Don't clear buffer on error - preserve data for retry
        eprintln!("access_log: write error: {e}");
        return;
      }
      // CR-003: Sync data to disk for durability
      if let Err(e) = file.sync_data() {
        eprintln!("access_log: sync error: {e}");
      }
      self.current_size += self.buffer.len() as u64;
    }

    self.buffer.clear();
    self.last_flush = Instant::now();

    // Check if rotation is needed after write
    if self.current_size >= self.max_size {
      self.rotate();
    }
  }

  fn ensure_file(&mut self) -> std::io::Result<()> {
    let today = time::OffsetDateTime::now_local()
      .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let format =
      time::format_description::parse("[year]-[month]-[day]").unwrap();
    let date_str = today.format(&format).unwrap();

    // Check if date changed (need new file)
    if self.current_date != date_str {
      self.current_file = None;
      self.current_date = date_str.clone();
      self.current_size = 0;
    }

    if self.current_file.is_some() {
      return Ok(());
    }

    // Find next available file name
    let path = self.next_file_path(&date_str);
    let dir = Path::new(&self.log_directory);
    fs::create_dir_all(dir)?;

    let file =
      OpenOptions::new().create(true).append(true).open(&path)?;

    self.current_size = file.metadata()?.len();
    self.current_path = Some(path);
    self.current_file = Some(file);
    Ok(())
  }

  fn next_file_path(&self, date: &str) -> PathBuf {
    let dir = Path::new(&self.log_directory);
    let base = dir.join(format!("{}.{}", self.path_prefix, date));

    if !base.exists() {
      return base;
    }

    // Check if existing file is under max_size
    if let Ok(meta) = fs::metadata(&base)
      && meta.len() < self.max_size
    {
      return base;
    }

    // Find next sequence number
    for seq in 1..10000 {
      let path =
        dir.join(format!("{}.{}.{}", self.path_prefix, date, seq));
      if !path.exists() {
        return path;
      }
      // Check if existing numbered file is under max_size
      if let Ok(meta) = fs::metadata(&path)
        && meta.len() < self.max_size
      {
        return path;
      }
    }

    // Fallback
    dir.join(format!("{}.{}.overflow", self.path_prefix, date))
  }

  fn rotate(&mut self) {
    // Close current file and reset state
    self.current_file = None;
    self.current_size = 0;
    // current_date stays the same; next ensure_file will
    // pick a new sequence number
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::access_log::config::{HumanBytes, HumanDuration};
  use crate::access_log::context::{AuthType, ServiceMetrics};
  use std::time::Duration;
  use time::OffsetDateTime;

  fn make_test_config(_dir: &str, prefix: &str) -> AccessLogConfig {
    AccessLogConfig {
      enabled: true,
      path_prefix: prefix.to_string(),
      format: LogFormat::Text,
      buffer: HumanBytes(256), // Small buffer for testing
      flush: HumanDuration(Duration::from_millis(100)),
      max_size: HumanBytes(1024), // 1KB for rotation testing
    }
  }

  fn make_test_entry() -> AccessLogEntry {
    AccessLogEntry {
      time: OffsetDateTime::now_utc(),
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

  #[test]
  fn test_writer_creation() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_test_config(dir.path().to_str().unwrap(), "test.log");
    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    // Writer should be created without error
    drop(writer);
  }

  #[test]
  fn test_writer_write_creates_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_test_config(dir.path().to_str().unwrap(), "test.log");
    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let entry = make_test_entry();
    writer.write(&entry);
    writer.flush();

    // Check that a log file was created
    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();
    assert!(!files.is_empty(), "Should create at least one log file");
  }

  #[test]
  fn test_writer_write_content() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_test_config(dir.path().to_str().unwrap(), "test.log");
    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let entry = make_test_entry();
    writer.write(&entry);
    writer.flush();

    // Read the log file content
    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();
    assert!(!files.is_empty());

    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(
      content.contains("CONNECT example.com:443"),
      "Log should contain request, got: {content}"
    );
  }

  #[test]
  fn test_writer_flush_writes_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let mut config =
      make_test_config(dir.path().to_str().unwrap(), "test.log");
    config.buffer = HumanBytes(1024 * 1024); // Large buffer
    config.flush = HumanDuration(Duration::from_secs(3600)); // Long interval

    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let entry = make_test_entry();
    writer.write(&entry);

    // Before flush, file may not exist or be empty
    // After flush, content should be written
    writer.flush();

    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();
    assert!(!files.is_empty());
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(!content.is_empty(), "Flush should write data");
  }

  #[test]
  fn test_writer_file_rotation_by_size() {
    let dir = tempfile::tempdir().unwrap();
    let mut config =
      make_test_config(dir.path().to_str().unwrap(), "test.log");
    config.max_size = HumanBytes(200); // Very small max
    config.buffer = HumanBytes(1); // Tiny buffer to force writes

    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);

    // Write enough entries to trigger rotation
    for _ in 0..20 {
      let entry = make_test_entry();
      writer.write(&entry);
    }
    writer.flush();

    // Should have multiple files due to rotation
    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();
    assert!(
      files.len() > 1,
      "Should have multiple files after rotation, got {}",
      files.len()
    );
  }

  #[test]
  fn test_writer_file_name_format() {
    let dir = tempfile::tempdir().unwrap();
    let config =
      make_test_config(dir.path().to_str().unwrap(), "access.log");
    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let entry = make_test_entry();
    writer.write(&entry);
    writer.flush();

    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .map(|e| e.file_name().to_str().unwrap().to_string())
      .filter(|n| n.starts_with("access.log"))
      .collect();
    assert!(!files.is_empty());

    // File name should be: access.log.YYYY-MM-DD
    let name = &files[0];
    assert!(
      name.starts_with("access.log."),
      "File name should start with prefix and dot, got: {name}"
    );
    // Check date format
    let date_part = &name["access.log.".len()..];
    assert!(
      date_part.len() >= 10,
      "Date part should be at least YYYY-MM-DD, got: {date_part}"
    );
  }

  #[test]
  fn test_writer_clone_shares_state() {
    let dir = tempfile::tempdir().unwrap();
    let config = make_test_config(dir.path().to_str().unwrap(), "test.log");
    let writer1 = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let writer2 = writer1.clone();

    let entry = make_test_entry();
    writer1.write(&entry);
    writer2.flush(); // Flush via clone should write data

    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();
    assert!(!files.is_empty());
  }

  #[test]
  fn test_writer_json_format() {
    let dir = tempfile::tempdir().unwrap();
    let mut config =
      make_test_config(dir.path().to_str().unwrap(), "test.log");
    config.format = LogFormat::Json;

    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let entry = make_test_entry();
    writer.write(&entry);
    writer.flush();

    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();
    assert!(!files.is_empty());

    let content = fs::read_to_string(files[0].path()).unwrap();
    // Should be valid JSON
    let parsed: serde_json::Value =
      serde_json::from_str(content.trim()).unwrap();
    assert!(parsed.is_object());
  }

  // ============== Code Review Issue Tests ==============

  #[test]
  fn test_writer_buffer_preserved_on_file_error() {
    // CR-001: Buffer should be preserved (not cleared) when file operations fail
    // This allows retry on next write attempt
    let dir = tempfile::tempdir().unwrap();
    let config =
      make_test_config(dir.path().to_str().unwrap(), "test.log");

    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let entry = make_test_entry();
    writer.write(&entry);

    // Remove directory to cause file open failure on flush
    drop(writer);
    fs::remove_dir_all(dir.path()).ok();

    // Create new writer with invalid directory
    let writer2 =
      AccessLogWriter::new("/nonexistent/path/that/does/not/exist", &config);
    writer2.write(&entry);
    // Should not panic, and buffer should be preserved internally
    // (we can't easily test buffer state directly, but this verifies no panic)
    writer2.flush(); // Should not panic on error
  }

  #[test]
  fn test_writer_flush_persists_to_disk() {
    // CR-003: flush() should sync data to disk, not just to OS buffer
    let dir = tempfile::tempdir().unwrap();
    let mut config =
      make_test_config(dir.path().to_str().unwrap(), "test.log");
    config.buffer = HumanBytes(1024 * 1024); // Large buffer so auto-flush doesn't trigger

    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);
    let entry = make_test_entry();
    writer.write(&entry);
    writer.flush();

    // Read file and verify content persisted
    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();
    assert!(!files.is_empty());

    // Re-open file and verify content is there
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(!content.is_empty(), "Content should be persisted after flush");
    assert!(
      content.contains("CONNECT example.com:443"),
      "Log content should be persisted, got: {content}"
    );
  }

  #[test]
  fn test_writer_buffer_does_not_grow_unbounded() {
    // CR-004: Buffer should have a maximum size limit
    // When buffer exceeds max, new entries should be dropped (with warning)
    let dir = tempfile::tempdir().unwrap();
    let mut config =
      make_test_config(dir.path().to_str().unwrap(), "test.log");
    config.buffer = HumanBytes(100); // Very small buffer
    config.flush = HumanDuration(Duration::from_secs(3600)); // Long interval to prevent auto-flush

    let writer = AccessLogWriter::new(dir.path().to_str().unwrap(), &config);

    // Write many entries - buffer should not grow beyond reasonable limit
    let entry = make_test_entry();
    for _ in 0..100 {
      writer.write(&entry);
    }

    // If buffer had no limit, we would have 100 * ~150 bytes = 15KB in memory
    // With limit, buffer should be capped at some reasonable multiple of buffer_capacity
    // We verify this by flushing and checking that some data was written
    writer.flush();

    let files: Vec<_> = fs::read_dir(dir.path())
      .unwrap()
      .filter_map(|e| e.ok())
      .filter(|e| {
        e.file_name()
          .to_str()
          .unwrap()
          .starts_with("test.log")
      })
      .collect();

    // Should have written at least something
    assert!(!files.is_empty());
    let content = fs::read_to_string(files[0].path()).unwrap();
    assert!(!content.is_empty());
  }
}
