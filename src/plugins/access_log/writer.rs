//! Simplified access log writer (single-threaded, no Arc<Mutex>).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::Instant;

use tracing::{error, warn};

use super::config::AccessLogWriterConfig;
use super::context::{AccessLogEntry, LogFormat};
use super::formatter;

pub struct AccessLogWriter {
  current_file: Option<File>,
  current_size: u64,
  current_date: String,
  buffer: Vec<u8>,
  last_flush: Instant,
  // Config-driven fields
  path_prefix: String,
  buffer_capacity: usize,
  max_buffer_size: usize,
  flush_interval: std::time::Duration,
  max_file_size: u64,
  rotate_daily: bool,
  format: LogFormat,
}

impl AccessLogWriter {
  pub fn from_config(config: &AccessLogWriterConfig) -> Self {
    Self {
      current_file: None,
      current_size: 0,
      current_date: String::new(),
      buffer: Vec::with_capacity(
        config.buffer_capacity.as_u64() as usize
      ),
      last_flush: Instant::now(),
      path_prefix: config.path_prefix.clone(),
      buffer_capacity: config.buffer_capacity.as_u64() as usize,
      max_buffer_size: config.max_buffer_size.as_u64() as usize,
      flush_interval: config.flush_interval,
      max_file_size: config.max_file_size.as_u64(),
      rotate_daily: config.rotate_daily,
      format: config.format,
    }
  }

  /// Legacy constructor with defaults for backward compatibility.
  /// Only used in tests; production code uses `from_config`.
  #[cfg(test)]
  pub fn new() -> Self {
    Self::from_config(&AccessLogWriterConfig::default())
  }

  pub fn write(&mut self, entry: &AccessLogEntry) {
    if self.buffer.len() >= self.max_buffer_size {
      warn!("access_log: buffer full, dropping entry");
      return;
    }

    let formatted = formatter::format_entry(entry, self.format);
    self.buffer.extend_from_slice(&formatted);

    if self.buffer.len() >= self.buffer_capacity
      || self.last_flush.elapsed() >= self.flush_interval
    {
      self.do_flush();
    }
  }

  pub fn flush(&mut self) {
    self.do_flush();
  }

  /// Flush only if the flush interval has elapsed.
  ///
  /// Called by the writer thread's periodic timeout path to ensure
  /// buffered entries are written even when no new entries arrive.
  pub fn flush_if_interval_elapsed(&mut self) {
    if self.last_flush.elapsed() >= self.flush_interval
      && !self.buffer.is_empty()
    {
      self.do_flush();
    }
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
        error!(
          "access_log: failed to write {} bytes to log file",
          self.buffer.len()
        );
        // CR-022: Reset current_file to None so that rotate_if_needed()
        // is triggered on the next flush to attempt opening a fresh
        // file. Without this, the broken file handle remains
        // and every subsequent flush fails silently
        // (rotate_if_needed sees current_file is not
        // None and doesn't try to open a new file).
        self.current_file = None;
      }
    } else {
      warn!(
        "access_log: discarding {} bytes of buffered data (no file \
         handle available)",
        self.buffer.len()
      );
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
      || (self.rotate_daily && self.current_date != today)
      || self.current_size >= self.max_file_size;

    if need_new_file {
      let path = if self.rotate_daily {
        std::path::PathBuf::from(format!(
          "{}.{}",
          self.path_prefix, today
        ))
      } else {
        std::path::PathBuf::from(&self.path_prefix)
      };
      if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
          if let Err(e) = std::fs::create_dir_all(parent) {
            error!(
              "access_log: failed to create directory '{}': {}",
              parent.display(),
              e
            );
          }
        }
      }

      match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => {
          self.current_file = Some(file);
          self.current_size = 0;
          self.current_date = today;
        }
        Err(e) => {
          error!("access_log: failed to open log file: {}", e);
          self.current_file = None;
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use byte_unit::Byte;

  use super::super::test_utils::TracingCapture;
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
  fn test_writer_from_config_custom_path() {
    let config = AccessLogWriterConfig {
      path_prefix: "logs/custom_access".to_string(),
      ..AccessLogWriterConfig::default()
    };
    let writer = AccessLogWriter::from_config(&config);
    assert!(writer.current_file.is_none());
    assert_eq!(writer.path_prefix, "logs/custom_access");
  }

  #[test]
  fn test_writer_from_config_json_format() {
    let config = AccessLogWriterConfig {
      format: LogFormat::Json,
      ..AccessLogWriterConfig::default()
    };
    let writer = AccessLogWriter::from_config(&config);
    assert_eq!(writer.format, LogFormat::Json);
  }

  #[test]
  fn test_writer_rotate_daily_false_uses_path_prefix_directly() {
    let dir = tempfile::tempdir().unwrap();
    let path_prefix =
      dir.path().join("logs/norotate").to_string_lossy().to_string();
    let config = AccessLogWriterConfig {
      path_prefix: path_prefix.clone(),
      rotate_daily: false,
      ..AccessLogWriterConfig::default()
    };
    let mut writer = AccessLogWriter::from_config(&config);
    let entry = make_entry();
    writer.write(&entry);
    writer.flush();

    // File should be at path_prefix directly (no date suffix)
    let path = std::path::PathBuf::from(&path_prefix);
    assert!(path.exists(), "Log file should exist at path_prefix");
  }

  #[test]
  fn test_writer_rotate_daily_true_uses_date_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let path_prefix =
      dir.path().join("logs/daily").to_string_lossy().to_string();
    let config = AccessLogWriterConfig {
      path_prefix: path_prefix.clone(),
      rotate_daily: true,
      ..AccessLogWriterConfig::default()
    };
    let mut writer = AccessLogWriter::from_config(&config);
    let entry = make_entry();
    writer.write(&entry);
    writer.flush();

    // File should be at path_prefix.YYYY-MM-DD
    let today = time::OffsetDateTime::now_utc()
      .format(
        &time::format_description::parse("[year]-[month]-[day]")
          .unwrap(),
      )
      .unwrap();
    let expected_path = format!("{}.{}", path_prefix, today);
    let path = std::path::PathBuf::from(&expected_path);
    assert!(path.exists(), "Log file should exist with date suffix");
  }

  #[test]
  fn test_writer_configurable_buffer_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let path_prefix =
      dir.path().join("logs/buf_cap").to_string_lossy().to_string();
    let config = AccessLogWriterConfig {
      path_prefix: path_prefix.clone(),
      buffer_capacity: Byte::from_u64(16), /* Very small to trigger
                                            * flush */
      ..AccessLogWriterConfig::default()
    };
    let mut writer = AccessLogWriter::from_config(&config);
    let entry = make_entry();
    writer.write(&entry);
    writer.flush();

    // With 16-byte buffer_capacity, a normal entry exceeds 16 bytes and
    // triggers flush-to-file. Verify the file exists and contains data.
    let today = time::OffsetDateTime::now_utc()
      .format(
        &time::format_description::parse("[year]-[month]-[day]")
          .unwrap(),
      )
      .unwrap();
    let expected_path = format!("{}.{}", path_prefix, today);
    let content = std::fs::read_to_string(&expected_path)
      .expect("Log file should exist after flush");
    assert!(
      !content.is_empty(),
      "Log file should contain written data"
    );
    assert!(
      content.contains("127.0.0.1"),
      "Log file should contain entry data"
    );
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
    let mut writer =
      AccessLogWriter::from_config(&AccessLogWriterConfig::default());
    writer.current_file = Some(file);
    writer.current_date = today;
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
    let config = AccessLogWriterConfig::default();
    let max_buf = config.max_buffer_size.as_u64() as usize;
    let mut writer = AccessLogWriter::new();
    writer.buffer.resize(max_buf, b'x');

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

    let mut writer =
      AccessLogWriter::from_config(&AccessLogWriterConfig::default());
    writer.current_file = Some(file);
    writer.current_date = today;

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

  #[test]
  fn test_writer_buffer_full_uses_tracing() {
    // CR-019: buffer full warning must go through tracing, not
    // eprintln!
    let (capture, _guard) = TracingCapture::new();

    let config = AccessLogWriterConfig::default();
    let max_buf = config.max_buffer_size.as_u64() as usize;
    let mut writer = AccessLogWriter::new();
    writer.buffer.resize(max_buf, b'x');

    let entry = make_entry();
    writer.write(&entry);

    // The entry should be dropped because buffer is full. The warning
    // must be captured by tracing (not eprintln!).
    let output = capture.output();
    assert!(
      output.contains("buffer full"),
      "tracing should capture 'buffer full' warning, got: {:?}",
      &output[..output.len().min(500)]
    );
  }

  #[test]
  fn test_writer_write_failure_uses_tracing() {
    // CR-019: write failure error must go through tracing, not
    // eprintln!
    let (capture, _guard) = TracingCapture::new();

    // Use a pipe with read end dropped so write fails with EPIPE
    let (pipe_reader, pipe_writer) = std::io::pipe().unwrap();
    drop(pipe_reader);

    use std::os::fd::{FromRawFd, IntoRawFd};
    let raw_fd = pipe_writer.into_raw_fd();
    let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };

    let today = time::OffsetDateTime::now_utc()
      .format(
        &time::format_description::parse("[year]-[month]-[day]")
          .unwrap(),
      )
      .unwrap();

    let mut writer =
      AccessLogWriter::from_config(&AccessLogWriterConfig::default());
    writer.current_file = Some(file);
    writer.current_date = today;

    let entry = make_entry();
    writer.write(&entry);
    writer.do_flush();

    // write_all fails with EPIPE, so the error must be captured by
    // tracing
    let output = capture.output();
    assert!(
      output.contains("failed to write"),
      "tracing should capture 'failed to write' error, got: {:?}",
      &output[..output.len().min(500)]
    );
  }

  #[test]
  fn test_writer_open_failure_uses_tracing() {
    // CR-019: file open failure error must go through tracing, not
    // eprintln!
    let (capture, _guard) = TracingCapture::new();

    // Create a regular file where a directory should be so that file
    // open fails. Use NamedTempFile for a unique path.
    let block_file = tempfile::NamedTempFile::new().unwrap();
    let block_path = block_file.path().to_string_lossy().to_string();

    let config = AccessLogWriterConfig {
      path_prefix: format!("{}/subdir/log", block_path),
      ..AccessLogWriterConfig::default()
    };
    let mut writer = AccessLogWriter::from_config(&config);

    // Force a flush which triggers rotate_if_needed, which tries to
    // open the file. The open will fail because the path traverses
    // through a regular file (block_file), not a directory.
    let entry = make_entry();
    writer.write(&entry);
    writer.do_flush();

    // The open failure must be captured by tracing
    let output = capture.output();
    assert!(
      output.contains("failed to open"),
      "tracing should capture 'failed to open' error, got: {:?}",
      &output[..output.len().min(500)]
    );
  }

  #[test]
  fn test_writer_create_dir_all_error_uses_tracing() {
    // CR-020: When create_dir_all fails in rotate_if_needed, the error
    // must be logged via tracing (not silently swallowed). Previously,
    // `let _ = std::fs::create_dir_all(parent)` discarded the error,
    // producing a misleading "failed to open log file" error when the
    // root cause was a directory creation failure.
    let (capture, _guard) = TracingCapture::new();

    // Create a regular file where a directory should be so that
    // create_dir_all fails. Use NamedTempFile for a unique path.
    let block_file = tempfile::NamedTempFile::new().unwrap();
    let block_path = block_file.path().to_string_lossy().to_string();

    let config = AccessLogWriterConfig {
      path_prefix: format!("{}/subdir/log", block_path),
      ..AccessLogWriterConfig::default()
    };
    let mut writer = AccessLogWriter::from_config(&config);

    // Force a flush which triggers rotate_if_needed, which tries
    // create_dir_all (fails because block_path is a regular file)
    // and then tries to open the file (also fails).
    let entry = make_entry();
    writer.write(&entry);
    writer.do_flush();

    // The create_dir_all failure must be captured by tracing.
    // With the bug, only "failed to open" is logged; the directory
    // creation error is silently swallowed.
    let output = capture.output();
    assert!(
      output.contains("failed to create directory"),
      "tracing should capture 'failed to create directory' error, \
       got: {:?}",
      &output[..output.len().min(500)]
    );
  }

  #[test]
  fn test_writer_discards_buffered_data_when_no_file_logs_warning() {
    // CR-021: When do_flush is called but current_file is None (because
    // rotate_if_needed failed to open a file), the buffered data is
    // silently discarded. This must be logged via tracing so that data
    // loss is observable in production. Without the fix, no warning is
    // emitted when buffered data is discarded.
    let (capture, _guard) = TracingCapture::new();

    // Create a regular file where a directory should be so that file
    // open fails, leaving current_file = None.
    let block_file = tempfile::NamedTempFile::new().unwrap();
    let block_path = block_file.path().to_string_lossy().to_string();

    let config = AccessLogWriterConfig {
      path_prefix: format!("{}/subdir/log", block_path),
      ..AccessLogWriterConfig::default()
    };
    let mut writer = AccessLogWriter::from_config(&config);

    // Write an entry to the buffer (but don't trigger auto-flush from
    // write() itself, since we want to control the flush timing)
    let entry = make_entry();
    writer.write(&entry);
    assert!(
      !writer.buffer.is_empty(),
      "Buffer should contain entry data"
    );

    // Now flush - rotate_if_needed will fail (can't open the file),
    // current_file will be None, and do_flush will discard the buffer.
    writer.do_flush();

    // The buffer discard must be captured by tracing as a warning.
    let output = capture.output();
    assert!(
      output.contains("discarding")
        && output.contains("no file handle"),
      "tracing should capture buffer discard warning, got: {:?}",
      &output[..output.len().min(500)]
    );
  }

  #[test]
  fn test_flush_if_interval_elapsed_flushes_when_elapsed_and_buffer_nonempty()
   {
    // SR-001: flush_if_interval_elapsed must flush when the interval
    // has elapsed and the buffer is non-empty.
    let dir = tempfile::tempdir().unwrap();
    let (mut writer, log_path) = make_writer_with_file(&dir);

    let entry = make_entry();
    writer.write(&entry);
    assert!(
      !writer.buffer.is_empty(),
      "Buffer should contain entry data"
    );

    // Set flush_interval to 1ms and last_flush to well in the past so
    // that the interval has definitely elapsed.
    writer.flush_interval = std::time::Duration::from_millis(1);
    writer.last_flush =
      Instant::now() - std::time::Duration::from_secs(10);

    writer.flush_if_interval_elapsed();

    // Buffer should be cleared (flush happened)
    assert!(
      writer.buffer.is_empty(),
      "Buffer should be cleared after flush"
    );
    // File should contain the entry
    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(!content.is_empty(), "File should contain flushed data");
    assert!(
      content.contains("127.0.0.1"),
      "File should contain entry data"
    );
  }

  #[test]
  fn test_flush_if_interval_elapsed_does_not_flush_when_interval_not_elapsed()
   {
    // SR-001: flush_if_interval_elapsed must NOT flush when the
    // interval has not elapsed, even if the buffer is non-empty.
    let dir = tempfile::tempdir().unwrap();
    let (mut writer, _log_path) = make_writer_with_file(&dir);

    let entry = make_entry();
    writer.write(&entry);
    assert!(
      !writer.buffer.is_empty(),
      "Buffer should contain entry data"
    );

    // Set flush_interval to 1 hour and last_flush to now so the
    // interval has NOT elapsed.
    writer.flush_interval = std::time::Duration::from_secs(3600);
    writer.last_flush = Instant::now();

    writer.flush_if_interval_elapsed();

    // Buffer should still contain data (no flush)
    assert!(
      !writer.buffer.is_empty(),
      "Buffer should still contain data when interval not elapsed"
    );
  }

  #[test]
  fn test_flush_if_interval_elapsed_does_not_flush_when_buffer_empty() {
    // SR-001: flush_if_interval_elapsed must NOT flush when the buffer
    // is empty, even if the interval has elapsed.
    let dir = tempfile::tempdir().unwrap();
    let (mut writer, _log_path) = make_writer_with_file(&dir);

    // Buffer is empty (no write call). Set interval to 1ms and
    // last_flush to well in the past.
    assert!(writer.buffer.is_empty(), "Buffer should start empty");
    writer.flush_interval = std::time::Duration::from_millis(1);
    writer.last_flush =
      Instant::now() - std::time::Duration::from_secs(10);

    writer.flush_if_interval_elapsed();

    // Should be a no-op (no panic, no error). Buffer still empty.
    assert!(
      writer.buffer.is_empty(),
      "Buffer should remain empty when flush_if_interval_elapsed \
       called with empty buffer"
    );
  }

  #[test]
  fn test_writer_write_failure_resets_current_file_to_none() {
    // CR-022: When file.write_all() fails in do_flush, current_file
    // must be reset to None so that rotate_if_needed() on the next
    // flush can attempt to open a fresh file. Without this fix, the
    // broken file handle remains and every subsequent flush fails
    // silently.
    let (capture, _guard) = TracingCapture::new();

    // Use a pipe with read end dropped so write fails with EPIPE
    let (pipe_reader, pipe_writer) = std::io::pipe().unwrap();
    drop(pipe_reader);

    use std::os::fd::{FromRawFd, IntoRawFd};
    let raw_fd = pipe_writer.into_raw_fd();
    let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };

    let today = time::OffsetDateTime::now_utc()
      .format(
        &time::format_description::parse("[year]-[month]-[day]")
          .unwrap(),
      )
      .unwrap();

    let mut writer =
      AccessLogWriter::from_config(&AccessLogWriterConfig::default());
    writer.current_file = Some(file);
    writer.current_date = today;

    let entry = make_entry();
    writer.write(&entry);
    assert!(!writer.buffer.is_empty());

    // do_flush: write_all will fail (EPIPE)
    writer.do_flush();

    // CR-022 fix: current_file must be None after write failure
    assert!(
      writer.current_file.is_none(),
      "current_file must be reset to None after write failure, so \
       rotate_if_needed can open a new file on next flush"
    );

    // Verify the error message includes byte count (observability
    // parity with CR-021)
    let output = capture.output();
    assert!(
      output.contains("failed to write") && output.contains("bytes"),
      "tracing should capture 'failed to write ... bytes' error, got: \
       {:?}",
      &output[..output.len().min(500)]
    );
  }
}
