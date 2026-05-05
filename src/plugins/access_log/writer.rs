//! Simplified access log writer (single-threaded, no Arc<Mutex>).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::Instant;

use super::context::{AccessLogEntry, LogFormat};
use super::formatter;

// Hardcoded configuration
const LOG_PATH: &str = "logs/access.log";
const BUFFER_CAPACITY: usize = 32 * 1024;
const MAX_BUFFER_SIZE: usize = 128 * 1024;
const FLUSH_INTERVAL: std::time::Duration =
  std::time::Duration::from_secs(1);
const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024;
const FORMAT: LogFormat = LogFormat::Text;

pub struct AccessLogWriter {
  current_file: Option<File>,
  current_size: u64,
  current_date: String,
  buffer: Vec<u8>,
  last_flush: Instant,
}

impl AccessLogWriter {
  pub fn new() -> Self {
    Self {
      current_file: None,
      current_size: 0,
      current_date: String::new(),
      buffer: Vec::with_capacity(BUFFER_CAPACITY),
      last_flush: Instant::now(),
    }
  }

  pub fn write(&mut self, entry: &AccessLogEntry) {
    if self.buffer.len() >= MAX_BUFFER_SIZE {
      eprintln!("access_log: buffer full, dropping entry");
      return;
    }

    let formatted = formatter::format_entry(entry, FORMAT);
    self.buffer.extend_from_slice(&formatted);

    if self.buffer.len() >= BUFFER_CAPACITY
      || self.last_flush.elapsed() >= FLUSH_INTERVAL
    {
      self.do_flush();
    }
  }

  pub fn flush(&mut self) {
    self.do_flush();
  }

  fn do_flush(&mut self) {
    if self.buffer.is_empty() {
      return;
    }

    self.rotate_if_needed();

    if let Some(ref mut file) = self.current_file {
      if file.write_all(&self.buffer).is_ok() {
        self.current_size += self.buffer.len() as u64;
      } else {
        eprintln!("access_log: failed to write to log file");
      }
    }

    self.buffer.clear();
    self.last_flush = Instant::now();
  }

  fn rotate_if_needed(&mut self) {
    let today = time::OffsetDateTime::now_utc()
      .format(
        &time::format_description::parse("[year]-[month]-[day]")
          .unwrap_or_default(),
      )
      .unwrap_or_default();

    let need_new_file = self.current_file.is_none()
      || self.current_date != today
      || self.current_size >= MAX_FILE_SIZE;

    if need_new_file {
      let path = std::path::PathBuf::from(LOG_PATH);
      if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
      }

      match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => {
          self.current_file = Some(file);
          self.current_size = 0;
          self.current_date = today;
        }
        Err(e) => {
          eprintln!("access_log: failed to open log file: {}", e);
          self.current_file = None;
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use super::*;

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
  fn test_access_log_writer_new() {
    let writer = AccessLogWriter::new();
    let _ = writer;
  }

  #[test]
  fn test_access_log_writer_has_no_file_before_flush() {
    let writer = AccessLogWriter::new();
    assert!(writer.current_file.is_none());
    assert_eq!(writer.current_size, 0);
  }

  #[test]
  fn test_access_log_writer_buffer_starts_empty() {
    let writer = AccessLogWriter::new();
    assert!(writer.buffer.is_empty());
  }

  #[test]
  fn test_access_log_writer_write_adds_to_buffer() {
    let mut writer = AccessLogWriter::new();
    let entry = make_entry();

    writer.write(&entry);

    // Buffer should have content now (formatted log entry)
    assert!(!writer.buffer.is_empty());
  }

  #[test]
  fn test_access_log_writer_multiple_writes_accumulate() {
    let mut writer = AccessLogWriter::new();
    let entry = make_entry();

    writer.write(&entry);
    let size_after_first = writer.buffer.len();

    writer.write(&entry);
    assert!(writer.buffer.len() > size_after_first);
  }

  /// Helper to create a writer with a properly initialized state
  /// so that rotate_if_needed won't try to open a new file.
  fn make_writer_with_file(
    dir: &tempfile::TempDir,
  ) -> (AccessLogWriter, std::path::PathBuf) {
    let log_path = dir.path().join("test.log");
    let file = OpenOptions::new()
      .create(true)
      .append(true)
      .open(&log_path)
      .unwrap();
    let today = time::OffsetDateTime::now_utc()
      .format(
        &time::format_description::parse("[year]-[month]-[day]")
          .unwrap(),
      )
      .unwrap();
    let writer = AccessLogWriter {
      current_file: Some(file),
      current_size: 0,
      current_date: today,
      buffer: Vec::with_capacity(BUFFER_CAPACITY),
      last_flush: Instant::now(),
    };
    (writer, log_path)
  }

  #[test]
  fn test_access_log_writer_flush_clears_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let (mut writer, _log_path) = make_writer_with_file(&dir);
    let entry = make_entry();

    writer.write(&entry);
    assert!(!writer.buffer.is_empty());

    writer.flush();
    assert!(writer.buffer.is_empty());
  }

  #[test]
  fn test_access_log_writer_flush_writes_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut writer, log_path) = make_writer_with_file(&dir);

    let entry = make_entry();
    writer.write(&entry);
    writer.flush();

    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(!content.is_empty());
    assert!(content.contains("127.0.0.1"));
    assert!(content.contains("200"));
  }

  #[test]
  fn test_access_log_writer_buffer_full_drops_entry() {
    let mut writer = AccessLogWriter::new();
    writer.buffer.resize(MAX_BUFFER_SIZE, b'x');

    let entry = make_entry();
    let size_before = writer.buffer.len();

    writer.write(&entry);

    // Buffer should not grow because entry was dropped
    assert_eq!(writer.buffer.len(), size_before);
  }

  #[test]
  fn test_access_log_writer_flush_on_empty_buffer_is_noop() {
    let mut writer = AccessLogWriter::new();
    // Should not panic or error
    writer.flush();
    assert!(writer.buffer.is_empty());
  }

  #[test]
  fn test_access_log_writer_size_not_incremented_on_write_failure() {
    // CR-015: current_size must not increment when write_all fails.
    // Use a pipe with read end dropped so write fails with EPIPE.
    let (pipe_reader, pipe_writer) = std::io::pipe().unwrap();
    // Drop the reader so writes to the writer end will fail with EPIPE
    drop(pipe_reader);

    // Take ownership of the raw fd without closing it, then wrap in
    // File.
    use std::os::fd::{FromRawFd, IntoRawFd};
    let raw_fd = pipe_writer.into_raw_fd();
    // SAFETY: raw_fd is a valid pipe write-end fd owned by us.
    let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };

    let today = time::OffsetDateTime::now_utc()
      .format(
        &time::format_description::parse("[year]-[month]-[day]")
          .unwrap(),
      )
      .unwrap();

    let mut writer = AccessLogWriter {
      current_file: Some(file),
      current_size: 0,
      current_date: today,
      buffer: Vec::with_capacity(BUFFER_CAPACITY),
      last_flush: Instant::now(),
    };

    let entry = make_entry();
    writer.write(&entry);
    assert!(!writer.buffer.is_empty());

    // do_flush attempts write_all which fails (EPIPE), then clears
    // buffer. The bug is that current_size is incremented despite
    // failure.
    writer.do_flush();

    assert_eq!(
      writer.current_size, 0,
      "current_size must not increment on write failure"
    );
  }
}
