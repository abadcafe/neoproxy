//! module: writer
//! responsibilities: persist buffered access entries to rotating files
//! public operations: AccessLogWriter::{from_config, with_date_source,
//! write, flush}
//! data entities: AccessLogWriter
//! tests: writer_tests.rs; test_access_log_rotation.py

use std::fs::{File, OpenOptions};
use std::io::Write;

use time::Date;
use time::error::IndeterminateOffset;
use tracing::{error, warn};

use super::config::AccessLogWriterConfig;
use super::context::{AccessLogEntry, LogFormat};
use super::formatter;
use super::paths::LogPaths;

pub(crate) struct AccessLogWriter {
  current_file: Option<File>,
  current_size: u64,
  current_date: Option<Date>,
  date_source: Box<dyn Fn() -> Result<Date, IndeterminateOffset>>,
  next_archive_index: u64,
  buffer: Vec<u8>,
  // Config-driven fields
  paths: LogPaths,
  buffer_capacity: usize,
  max_buffer_size: usize,
  max_file_size: u64,
  rotate_daily: bool,
  format: LogFormat,
}

impl AccessLogWriter {
  pub(crate) fn from_config(config: &AccessLogWriterConfig) -> Self {
    Self::with_date_source(config, || {
      time::OffsetDateTime::now_local().map(|now| now.date())
    })
  }

  /// The source supplies the current calendar date at flush time.
  /// Production uses the process's local timezone, including its DST
  /// rules. Injecting the source makes calendar transitions testable
  /// without changing the process clock or global timezone state.
  pub(crate) fn with_date_source(
    config: &AccessLogWriterConfig,
    date_source: impl Fn() -> Result<Date, IndeterminateOffset> + 'static,
  ) -> Self {
    Self {
      current_file: None,
      current_size: 0,
      current_date: None,
      date_source: Box::new(date_source),
      next_archive_index: 1,
      buffer: Vec::with_capacity(
        config.buffer_capacity.as_u64() as usize
      ),
      paths: LogPaths::new(
        config.path_prefix.clone().into(),
        config.rotate_daily,
      ),
      buffer_capacity: config.buffer_capacity.as_u64() as usize,
      max_buffer_size: config.max_buffer_size.as_u64() as usize,
      max_file_size: config.max_file_size.as_u64(),
      rotate_daily: config.rotate_daily,
      format: config.format,
    }
  }

  pub(crate) fn write(&mut self, entry: &AccessLogEntry) {
    let formatted = formatter::format_entry(entry, self.format);
    if formatted.len() > self.max_buffer_size {
      warn!("access_log: entry exceeds buffer limit, dropping entry");
      return;
    }
    if self.buffer.len().saturating_add(formatted.len())
      > self.max_buffer_size
    {
      self.do_flush();
    }

    self.buffer.extend_from_slice(&formatted);

    // The registry thread owns time-based flushing; this writer owns
    // byte-buffer capacity and explicit persistence only.
    if self.buffer.len() >= self.buffer_capacity {
      self.do_flush();
    }
  }

  pub(crate) fn flush(&mut self) {
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
  }

  fn rotate_if_needed(&mut self) {
    let today = if self.rotate_daily {
      match (self.date_source)() {
        Ok(date) => Some(date),
        Err(error) => {
          // Do not silently use UTC or keep writing into a file whose
          // local date could no longer be determined.
          error!("access_log: failed to determine local date: {error}");
          self.current_file = None;
          return;
        }
      }
    } else {
      None
    };
    if self.current_date != today {
      self.current_file = None;
      // Numbering belongs to the dated active path. Reopening a past
      // date will find its occupied numbers through the same collision
      // handling used after a restart.
      self.next_archive_index = 1;
    }
    if self.current_file.is_some()
      && self.current_size < self.max_file_size
    {
      return;
    }
    let path = self.paths.active(today);
    if self.current_file.is_none() {
      match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => {
          match file.metadata() {
            Ok(metadata) => self.current_size = metadata.len(),
            Err(error) => {
              error!("access_log: failed to stat log file: {error}");
              return;
            }
          }
          self.current_file = Some(file);
          self.current_date = today;
        }
        Err(error) => {
          error!("access_log: failed to open log file: {error}");
          return;
        }
      }
    }
    if self.current_size >= self.max_file_size && self.current_size > 0
    {
      // hard_link creates a new archive without overwriting any earlier
      // archive, including archives created before a process restart.
      // Remember the next candidate after both success and collision.
      // Existing archives are probed once after startup/path changes;
      // later rotations do not rescan the numbers already consumed.
      loop {
        let index = self.next_archive_index;
        let Some(next_index) = index.checked_add(1) else {
          error!("access_log: archive index exhausted");
          return;
        };
        let archive = self.paths.archive(today, index);
        match std::fs::hard_link(&path, &archive) {
          Ok(()) => {
            self.next_archive_index = next_index;
            break;
          }
          Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists =>
          {
            self.next_archive_index = next_index;
          }
          Err(error) => {
            error!("access_log: failed to archive log: {error}");
            return;
          }
        }
      }
      self.current_file = None;
      if let Err(error) = std::fs::remove_file(&path) {
        error!("access_log: failed to remove archived log: {error}");
        return;
      }
      match OpenOptions::new().create_new(true).append(true).open(&path)
      {
        Ok(file) => {
          self.current_file = Some(file);
          self.current_size = 0;
        }
        Err(error) => {
          error!("access_log: failed to open rotated log: {error}")
        }
      }
    }
  }
}
