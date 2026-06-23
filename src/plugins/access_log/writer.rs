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

  pub fn write(&mut self, entry: &AccessLogEntry) {
    let formatted = formatter::format_entry(entry, self.format);
    if self.buffer.len().saturating_add(formatted.len())
      > self.max_buffer_size
    {
      warn!("access_log: buffer full, dropping entry");
      return;
    }

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
