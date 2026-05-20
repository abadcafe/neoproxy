//! Writer registry: manages named writer threads.

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Mutex;

use tracing::warn;

use super::config::AccessLogPluginConfig;
use super::context::AccessLogEntry;
use super::writer::AccessLogWriter;

/// Channel capacity
const QUEUE_SIZE: usize = 4096;

/// Timeout for joining writer threads during reinit or test cleanup.
///
/// Shorter than `super::WRITER_JOIN_TIMEOUT` because during reinit the old
/// writer threads should exit quickly (all Senders from the registry are
/// dropped). The shorter timeout prevents unnecessary delays during
/// configuration changes. If a thread doesn't exit within this time, it
/// is detached and will be joined during process shutdown (using
/// `super::WRITER_JOIN_TIMEOUT`).
const WRITER_REINIT_JOIN_TIMEOUT: std::time::Duration =
  std::time::Duration::from_secs(2);

/// Log entry sent through channel.
pub struct LogEntry {
  pub entry: AccessLogEntry,
}

/// Global writer registry (shared across all server threads).
///
/// Uses `Mutex<Option<...>>` instead of `OnceLock` to allow test
/// isolation: tests can call `reset_writer_registry()` between runs
/// to clear the registry and re-initialize with different configs.
/// In production, the registry is set once during plugin init and
/// never reset.
pub(crate) static WRITER_REGISTRY: Mutex<Option<HashMap<String, WriterHandle>>> =
  Mutex::new(None);

/// Handle to a named writer thread.
pub struct WriterHandle {
  tx: mpsc::SyncSender<LogEntry>,
  pub(crate) join_handle: Option<std::thread::JoinHandle<()>>,
}

impl WriterHandle {
  pub fn sender(&self) -> mpsc::SyncSender<LogEntry> {
    self.tx.clone()
  }
}

/// Initialize the writer registry from plugin config.
///
/// Called once during plugin initialization. Spawns one thread per
/// writer config entry. Validates/creates the log directory for each
/// writer at init time (spec: "Writer path can't be created -> error
/// at init time, not at runtime").
///
/// If the registry is already initialized with the same set of
/// path_prefixes, returns `Ok(())` (idempotent); each server thread
/// calls this via `PluginManager::new()`, so the idempotent behavior
/// is essential for correctness in production. If the registry is
/// initialized with a different set of path_prefixes (e.g., after a
/// test called `reset_writer_registry()` and another test's
/// `PluginManager::new()` initialized with empty writers), the old
/// writers are shut down and the registry is reinitialized with the
/// new config.
///
/// The WRITER_REGISTRY Mutex lock is held only during the minimal
/// critical sections (idempotency check and registry swap). Directory
/// creation, thread spawning, and joining old writer threads are done
/// outside the lock to avoid blocking `get_writer()` callers.
pub fn init_writer_registry(config: &AccessLogPluginConfig) -> anyhow::Result<()> {
  // Phase 1: Under the lock, check idempotency and take old registry.
  // This is the minimal critical section - only quick operations.
  let old_registry = {
    let mut guard = WRITER_REGISTRY.lock().unwrap();

    // Check if already initialized with the same writer path_prefixes
    if let Some(existing) = guard.as_ref() {
      let existing_prefixes: std::collections::HashSet<&String> =
        existing.keys().collect();
      let requested_prefixes: std::collections::HashSet<&String> =
        config.writers.iter().map(|w| &w.path_prefix).collect();
      if existing_prefixes == requested_prefixes {
        // Already initialized with the same writers - idempotent
        return Ok(());
      }
      // Different writers - need to reinitialize. Take the old registry
      // out so we can shut down old writers outside the lock.
      guard.take()
    } else {
      None
    }
  };
  // Lock is released here.

  // Phase 2: Join old writer threads (outside lock).
  // This can take up to WRITER_REINIT_JOIN_TIMEOUT per thread, so it
  // must not hold the lock or get_writer() callers would be blocked.
  if let Some(old) = old_registry {
    join_writer_handles(old, "reinit cleanup");
  }

  // Phase 3: Validate duplicate path_prefixes (no lock needed, pure
  // config check). This prevents silent overwrites that would orphan
  // writer threads.
  let mut seen_prefixes = HashMap::new();
  for (i, writer_config) in config.writers.iter().enumerate() {
    if let Some(&prev_idx) = seen_prefixes.get(&writer_config.path_prefix) {
      return Err(anyhow::anyhow!(
        "duplicate writer path_prefix: '{}' (defined at index {} and {})",
        writer_config.path_prefix,
        prev_idx,
        i
      ));
    }
    seen_prefixes.insert(&writer_config.path_prefix, i);
  }

  // Phase 4a: Validate all directories before spawning any threads
  // (CR-015 fix). This prevents partial failure where some threads are
  // spawned but the registry is not committed. Directory creation can
  // be slow but must not block get_writer() callers (lock not held).
  for writer_config in &config.writers {
    let path = std::path::PathBuf::from(&writer_config.path_prefix);
    if let Some(parent) = path.parent() {
      if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent).map_err(|e| {
          anyhow::anyhow!(
            "access_log: failed to create directory for writer '{}': {}",
            writer_config.path_prefix, e
          )
        })?;
      }
    }
  }

  // Phase 4b: Spawn writer threads (outside lock). If thread spawning
  // fails partway through, roll back by joining already-spawned threads
  // before returning the error (CR-015 fix). This ensures no orphaned
  // writer threads are left running when init_writer_registry returns
  // an error.
  let mut new_registry = HashMap::new();
  for writer_config in &config.writers {
    let (tx, rx): (mpsc::SyncSender<LogEntry>, mpsc::Receiver<LogEntry>) =
      mpsc::sync_channel(QUEUE_SIZE);

    // Clone path_prefix BEFORE moving config into the thread closure
    // to avoid use-after-move
    let config = writer_config.clone();
    let path_prefix = config.path_prefix.clone();
    let flush_interval = config.flush_interval;

    let join_handle = std::thread::Builder::new()
      .name(format!("access-log-writer-{}", path_prefix))
      .spawn(move || {
        let mut wtr = AccessLogWriter::from_config(&config);
        loop {
          match rx.recv_timeout(flush_interval) {
            Ok(log) => wtr.write(&log.entry),
            Err(mpsc::RecvTimeoutError::Timeout) => {
              // Periodic flush: ensure buffered entries are written
              // even when no new entries arrive
              wtr.flush_if_interval_elapsed();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
          }
        }
        wtr.flush();
      });

    match join_handle {
      Ok(jh) => {
        new_registry.insert(path_prefix, WriterHandle { tx, join_handle: Some(jh) });
      }
      Err(e) => {
        // Thread spawn failed. Roll back: join already-spawned threads
        // before returning the error. This prevents orphaned writer
        // threads that would be detached when new_registry is dropped.
        join_writer_handles(new_registry, "partial init rollback");
        return Err(anyhow::anyhow!(
          "access_log: failed to spawn writer thread for '{}': {}",
          path_prefix, e
        ));
      }
    }
  }

  // Phase 5: Under the lock, insert the new registry.
  // This is the minimal critical section - just a swap.
  {
    let mut guard = WRITER_REGISTRY.lock().unwrap();
    // If another thread initialized the registry while we were working
    // (unlikely in practice due to idempotency and serial_test), shut
    // down our threads and return. In production this can't happen
    // because the idempotent check prevents concurrent init calls; in
    // tests, serial_test prevents concurrent access.
    if guard.is_some() {
      // Another thread beat us; shut down our newly spawned threads.
      // Drop the lock before joining to avoid blocking get_writer()
      // callers (CR-010). Use join_writer_handles which has a per-thread
      // timeout to prevent indefinite blocking if a writer thread hangs
      // (CR-012).
      drop(guard);
      join_writer_handles(new_registry, "concurrent init cleanup");
      return Ok(());
    }
    *guard = Some(new_registry);
  }

  Ok(())
}

/// Join writer handles from a previous registry, with a timeout per
/// thread. Used during reinit (when the registry is reinitialized with
/// different writers) and during test cleanup.
///
/// Takes the handles out of the WriterHandle structs (dropping the
/// Senders, which signals the writer threads to exit), then joins
/// each thread with a `WRITER_REINIT_JOIN_TIMEOUT` timeout.
pub(crate) fn join_writer_handles(
  registry: HashMap<String, WriterHandle>,
  context: &str,
) {
  // Extract JoinHandles and drop Senders
  let mut join_handles: Vec<(String, std::thread::JoinHandle<()>)> = vec![];
  for (path_prefix, mut handle) in registry {
    if let Some(jh) = handle.join_handle.take() {
      join_handles.push((path_prefix, jh));
    }
    // handle (and its Sender) is dropped here
  }

  // Join old writer threads (with a short timeout since they should
  // exit quickly once all Senders are dropped)
  join_writer_threads(join_handles, WRITER_REINIT_JOIN_TIMEOUT, context);
}

/// Look up a writer by path_prefix.
///
/// Returns an error if the writer is not found in the registry.
pub fn get_writer(path_prefix: &str) -> anyhow::Result<mpsc::SyncSender<LogEntry>> {
  let guard = WRITER_REGISTRY.lock().unwrap();
  let registry = guard.as_ref().ok_or_else(|| {
    anyhow::anyhow!("access_log writer registry not initialized")
  })?;
  registry.get(path_prefix).map(|h| h.sender()).ok_or_else(|| {
    anyhow::anyhow!(
      "access_log writer '{}' not found in registry",
      path_prefix
    )
  })
}

/// Reset the writer registry (test only).
///
/// Takes the old registry out (under the lock), then joins each writer
/// thread (outside the lock) to ensure it has fully exited and flushed
/// before returning. This prevents test interference: without joining,
/// detached writer threads from a previous test may still be running
/// (holding file handles) when the next test starts.
#[cfg(test)]
pub fn reset_writer_registry() {
  let old_registry = {
    let mut guard = WRITER_REGISTRY.lock().unwrap();
    guard.take()
  };

  if let Some(registry) = old_registry {
    join_writer_handles(registry, "test cleanup");
  }
}

/// Join writer threads with a timeout per thread.
///
/// Used by `join_writer_handles` (reinit/test cleanup) and
/// `uninstall` (shutdown).
/// Spawns a helper thread for each join to avoid
/// blocking indefinitely if a writer thread's final flush hangs due
/// to an unresponsive filesystem.
pub(crate) fn join_writer_threads(
  handles: Vec<(String, std::thread::JoinHandle<()>)>,
  timeout: std::time::Duration,
  context: &str,
) {
  for (path_prefix, jh) in handles {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
      let result = jh.join();
      let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
      Ok(Ok(())) => {}
      Ok(Err(_)) => {
        warn!(
          "access_log: writer thread '{}' panicked during {}",
          path_prefix, context
        );
      }
      Err(_) => {
        warn!(
          "access_log: writer thread '{}' did not exit within \
           {:?} during {}, detaching",
          path_prefix, timeout, context
        );
      }
    }
  }
}
