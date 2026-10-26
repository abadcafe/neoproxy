//! module: registry
//! responsibilities: own and flush a process's access log writer
//! threads
//! public operations: WriterRegistry::{new, get_writer}
//! data entities: WriterHandle, WriterRegistry, ChannelSink
//! tests: registry_tests.rs

use std::collections::HashMap;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};

use super::config::AccessLogPluginConfig;
use super::context::AccessLogEntry;
use super::paths::LogPaths;
use super::writer::AccessLogWriter;

const QUEUE_SIZE: usize = 4096;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct WriterHandle {
  sender: mpsc::SyncSender<AccessLogEntry>,
  thread: std::thread::JoinHandle<()>,
}

pub(crate) struct WriterRegistry {
  writers: HashMap<String, WriterHandle>,
}

impl WriterRegistry {
  pub(crate) fn new(config: &AccessLogPluginConfig) -> Result<Self> {
    let mut names = std::collections::HashSet::new();
    let mut paths: Vec<LogPaths> = Vec::new();
    for writer in &config.writers {
      ensure!(
        names.insert(&writer.path_prefix),
        "duplicate writer path_prefix: {}",
        writer.path_prefix
      );
      ensure!(
        !writer.path_prefix.is_empty(),
        "writer path_prefix must not be empty"
      );
      ensure!(
        !writer.flush_interval.is_zero()
          && Instant::now()
            .checked_add(writer.flush_interval)
            .is_some(),
        "writer flush_interval must be positive and representable"
      );
      ensure!(
        writer.buffer_capacity.as_u64() > 0
          && writer.buffer_capacity <= writer.max_buffer_size,
        "writer buffer_capacity must be positive and <= \
         max_buffer_size"
      );
      ensure!(
        writer.max_file_size.as_u64() > 0,
        "writer max_file_size must be positive"
      );
      ensure!(
        isize::try_from(writer.buffer_capacity.as_u64()).is_ok()
          && usize::try_from(writer.max_buffer_size.as_u64()).is_ok(),
        "writer buffer sizes must fit platform allocation limits"
      );
      let path = std::path::Path::new(&writer.path_prefix);
      if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
      {
        std::fs::create_dir_all(parent)?;
      }
      ensure!(
        !path.is_dir(),
        "writer path is a directory: {}",
        path.display()
      );
      let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
      let filename = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
          "writer path has no file name: {}",
          path.display()
        )
      })?;
      let canonical = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
          std::fs::canonicalize(parent)?.join(filename)
        }
        Err(error) => return Err(error.into()),
      };
      let destination = LogPaths::new(canonical, writer.rotate_daily);
      ensure!(
        paths.iter().all(|previous| !destination.overlaps(previous)),
        "multiple writers own the same log path: {}",
        path.display()
      );
      paths.push(destination);
    }
    let mut registry = Self { writers: HashMap::new() };
    for config in &config.writers {
      let (sender, receiver) =
        mpsc::sync_channel::<AccessLogEntry>(QUEUE_SIZE);
      let config = config.clone();
      let name = config.path_prefix.clone();
      let thread = std::thread::Builder::new()
        .name(format!("access-log-{name}"))
        .spawn(move || {
          let mut writer = AccessLogWriter::from_config(&config);
          let mut deadline = Instant::now() + config.flush_interval;
          loop {
            match receiver.recv_timeout(
              deadline.saturating_duration_since(Instant::now()),
            ) {
              Ok(log) => writer.write(&log),
              Err(mpsc::RecvTimeoutError::Timeout) => {}
              Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() >= deadline {
              // This thread owns the periodic deadline. A size flush
              // must not suppress this tick: any subsequently buffered
              // entries still have to be persisted within one interval.
              writer.flush();
              deadline = Instant::now() + config.flush_interval;
            }
          }
          writer.flush();
        })?;
      registry.writers.insert(name, WriterHandle { sender, thread });
    }
    Ok(registry)
  }

  pub(crate) fn get_writer(
    &self,
    name: &str,
  ) -> Result<Arc<dyn super::layer::LogSink>> {
    self
      .writers
      .get(name)
      .map(|handle| {
        Arc::new(ChannelSink(handle.sender.clone()))
          as Arc<dyn super::layer::LogSink>
      })
      .ok_or_else(|| {
        anyhow::anyhow!("access_log writer '{name}' not found")
      })
  }
}

impl Drop for WriterRegistry {
  fn drop(&mut self) {
    let mut handles = Vec::new();
    for (name, writer) in self.writers.drain() {
      handles.push((name, writer.thread));
    }
    if handles.is_empty() {
      return;
    }
    let (sender, receiver) = mpsc::channel();
    // One budget for the entire registry, independent of writer count.
    std::thread::spawn(move || {
      for (name, handle) in handles {
        if handle.join().is_err() {
          tracing::error!("access_log writer '{name}' panicked");
        }
      }
      let _ = sender.send(());
    });
    if receiver.recv_timeout(SHUTDOWN_TIMEOUT).is_err() {
      tracing::warn!("access_log writers exceeded shutdown budget");
    }
  }
}

struct ChannelSink(mpsc::SyncSender<AccessLogEntry>);
impl super::layer::LogSink for ChannelSink {
  fn record(
    &self,
    entry: AccessLogEntry,
  ) -> Result<(), super::layer::DeliveryError> {
    self.0.try_send(entry).map_err(|error| match error {
      mpsc::TrySendError::Full(_) => super::layer::DeliveryError::Full,
      mpsc::TrySendError::Disconnected(_) => {
        super::layer::DeliveryError::Stopped
      }
    })
  }
}
