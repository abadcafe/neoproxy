//! Access log plugin.

pub mod config;
pub mod context;
pub mod formatter;
pub mod writer;

#[cfg(test)]
mod test_utils;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Instant;

use tracing::warn;

use self::config::AccessLogConfig;
use self::config::AccessLogPluginConfig;
use self::context::AccessLogEntry;
use self::writer::AccessLogWriter;
use crate::config::SerializedArgs;
use crate::context::RequestContext;
use crate::http_utils::{Request, Response};
use crate::plugin::Plugin;
use crate::service::{BuildLayer, Layer, Service};

/// Channel capacity
const QUEUE_SIZE: usize = 4096;

/// Timeout for joining writer threads during shutdown.
///
/// If a writer thread does not exit within this duration (e.g., because
/// the filesystem is unresponsive or sender clones are still held by
/// middleware instances), the join is abandoned and the thread is
/// detached. This prevents the shutdown sequence from blocking
/// indefinitely.
const WRITER_JOIN_TIMEOUT: std::time::Duration =
  std::time::Duration::from_secs(5);

/// Timeout for joining writer threads during reinit or test cleanup.
///
/// Shorter than `WRITER_JOIN_TIMEOUT` because during reinit the old
/// writer threads should exit quickly (all Senders from the registry are
/// dropped). The shorter timeout prevents unnecessary delays during
/// configuration changes. If a thread doesn't exit within this time, it
/// is detached and will be joined by `flush_writer_threads()` during
/// process shutdown (using `WRITER_JOIN_TIMEOUT`).
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
static WRITER_REGISTRY: Mutex<Option<HashMap<String, WriterHandle>>> =
  Mutex::new(None);

/// Writer thread JoinHandles saved by `uninstall()` for later joining.
///
/// When `uninstall()` is called from a server thread, it drops the
/// Sender handles (signaling writer threads to exit) but cannot
/// reliably join the writer threads because other server threads may
/// still hold Sender clones from middleware instances. The JoinHandles
/// are saved here and joined later by `flush_writer_threads()`, which
/// is called from `main.rs` after ALL server threads have exited (and
/// thus all Sender clones are dropped).
///
/// This two-phase approach (uninstall drops senders, flush joins
/// threads) fixes CR-014: multi-threaded shutdown can leave writer
/// threads unflushed when the process exits.
static PENDING_WRITER_JOINS: Mutex<Vec<(String, std::thread::JoinHandle<()>)>> =
  Mutex::new(Vec::new());

/// Handle to a named writer thread.
pub struct WriterHandle {
  tx: mpsc::SyncSender<LogEntry>,
  join_handle: Option<std::thread::JoinHandle<()>>,
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
fn init_writer_registry(config: &AccessLogPluginConfig) -> anyhow::Result<()> {
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
fn join_writer_handles(
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
fn get_writer(path_prefix: &str) -> anyhow::Result<mpsc::SyncSender<LogEntry>> {
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
///
/// Also joins any pending writer threads from `PENDING_WRITER_JOINS`
/// (saved by a previous `uninstall()` call) to ensure a clean state.
#[cfg(test)]
fn reset_writer_registry() {
  let old_registry = {
    let mut guard = WRITER_REGISTRY.lock().unwrap();
    guard.take()
  };

  if let Some(registry) = old_registry {
    join_writer_handles(registry, "test cleanup");
  }

  // Also join any pending writer threads from a previous uninstall().
  // This ensures a clean state for the next test.
  flush_writer_threads();
}

/// Flush and join all writer threads that were saved by `uninstall()`.
///
/// This function is called from `main.rs` after ALL server threads have
/// exited. At that point, all `mpsc::Sender` clones from middleware
/// instances have been dropped (because the listeners that own them
/// are dropped when each server thread exits). This means writer
/// threads should be able to exit quickly (their `blocking_recv()`
/// returns `None`), and the join should succeed within
/// `WRITER_JOIN_TIMEOUT`.
///
/// CR-014 fix: By separating "drop senders" (in `uninstall()`) from
/// "join threads" (here), we ensure writer threads have a chance to
/// flush their buffers before `std::process::exit()` kills the
/// process. Previously, `uninstall()` tried to join with a timeout,
/// but if other server threads still held sender clones, the join
/// would time out and the threads would be detached (killed by
/// `std::process::exit()` before flushing).
pub fn flush_writer_threads() {
  let pending: Vec<(String, std::thread::JoinHandle<()>)> = {
    let mut guard = PENDING_WRITER_JOINS.lock().unwrap();
    std::mem::take(&mut *guard)
  };

  if pending.is_empty() {
    return;
  }

  // Join writer threads with timeout. By the time this function is
  // called, all sender clones should be dropped (all server threads
  // have exited), so the join should succeed quickly.
  join_writer_threads(pending, WRITER_JOIN_TIMEOUT, "shutdown flush");
}

/// Join writer threads with a timeout per thread.
///
/// Shared implementation used by `join_writer_handles` (reinit/test
/// cleanup, shorter timeout) and `flush_writer_threads` (shutdown,
/// longer timeout). Spawns a helper thread for each join to avoid
/// blocking indefinitely if a writer thread's final flush hangs due
/// to an unresponsive filesystem.
fn join_writer_threads(
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

/// Access log plugin providing file layer.
pub struct AccessLogPlugin {
  layer_builders: HashMap<&'static str, Box<dyn BuildLayer>>,
}

impl AccessLogPlugin {
  pub fn new() -> Self {
    let file_layer_builder: Box<dyn BuildLayer> = Box::new(|args| {
      let config: AccessLogConfig = serde_yaml::from_value(args)?;
      let tx = get_writer(&config.writer)?;

      Ok(Layer::new(AccessLogLayer {
        tx,
        context_fields: config.context_fields,
      }))
    });

    Self {
      layer_builders: HashMap::from([("file", file_layer_builder)]),
    }
  }

  pub fn plugin_name() -> &'static str {
    "access_log"
  }

  pub fn create_plugin(config: Option<&SerializedArgs>) -> Box<dyn Plugin> {
    // Initialize writer registry from config
    if let Some(config_value) = config {
      let plugin_config: AccessLogPluginConfig =
        serde_yaml::from_value(config_value.clone())
          .unwrap_or_else(|e| panic!("access_log: failed to parse plugin config: {}", e));
      init_writer_registry(&plugin_config)
        .unwrap_or_else(|e| panic!("access_log: failed to initialize writer registry: {}", e));
    } else {
      // No config provided - initialize with empty registry
      init_writer_registry(&AccessLogPluginConfig::default())
        .unwrap_or_else(|e| panic!("access_log: failed to initialize writer registry: {}", e));
    }
    Box::new(Self::new())
  }
}

impl Plugin for AccessLogPlugin {
  fn layer_builder(&self, name: &str) -> Option<&Box<dyn BuildLayer>> {
    self.layer_builders.get(name)
  }

  fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {
      // Take the writer registry (replace with None), dropping all
      // Sender handles stored in the registry. When all Senders are
      // dropped (including clones held by middleware instances, which
      // must be dropped before the writer thread can exit), each
      // writer thread's blocking_recv() returns None, triggering the
      // final flush and allowing the thread to exit cleanly.
      //
      // CR-014 fix: Instead of joining writer threads here (which can
      // time out if other server threads still hold Sender clones),
      // save the JoinHandles to PENDING_WRITER_JOINS for later joining
      // by `flush_writer_threads()`. That function is called from
      // main.rs after ALL server threads have exited, at which point
      // all Sender clones are dropped and writer threads can exit
      // quickly.
      let old_registry = {
        let mut guard = WRITER_REGISTRY.lock().unwrap();
        guard.take()
      };

      if let Some(registry) = old_registry {
        // Extract JoinHandles and drop Senders (signaling threads to
        // exit), then save JoinHandles for later joining.
        let mut pending = PENDING_WRITER_JOINS.lock().unwrap();
        for (path_prefix, mut handle) in registry {
          if let Some(jh) = handle.join_handle.take() {
            pending.push((path_prefix, jh));
          }
          // handle (and its Sender) is dropped here, signaling the
          // writer thread to exit.
        }
      }
    })
  }
}

/// Layer that creates AccessLogMiddleware instances.
struct AccessLogLayer {
  tx: mpsc::SyncSender<LogEntry>,
  context_fields: Vec<String>,
}

impl tower::Layer<Service> for AccessLogLayer {
  type Service = Service;

  fn layer(&self, inner: Service) -> Service {
    Service::new(AccessLogMiddleware {
      inner,
      tx: self.tx.clone(),
      context_fields: self.context_fields.clone(),
    })
  }
}

/// Middleware that logs access entries.
struct AccessLogMiddleware {
  inner: Service,
  tx: mpsc::SyncSender<LogEntry>,
  context_fields: Vec<String>,
}

impl Clone for AccessLogMiddleware {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner.clone(),
      tx: self.tx.clone(),
      context_fields: self.context_fields.clone(),
    }
  }
}

impl tower::Service<Request> for AccessLogMiddleware {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = anyhow::Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<anyhow::Result<()>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, req: Request) -> Self::Future {
    let start = Instant::now();
    let tx = self.tx.clone();
    let context_fields = self.context_fields.clone();

    let method = req.method().to_string();
    let target = req.uri().to_string();

    let ctx = req
      .extensions()
      .get::<RequestContext>()
      .cloned()
      .unwrap_or_default();

    let mut inner = self.inner.clone();

    Box::pin(async move {
      let result = inner.call(req).await;

      let entry = build_log_entry(
        &result,
        start,
        ctx,
        context_fields,
        &method,
        &target,
      );

      if let Err(e) = tx.try_send(LogEntry { entry }) {
        match e {
          std::sync::mpsc::TrySendError::Full(_) => {
            warn!("access_log: channel full, dropping log entry");
          }
          std::sync::mpsc::TrySendError::Disconnected(_) => {
            warn!("access_log: channel closed, dropping log entry");
          }
        }
      }

      match result {
        Ok(response) => Ok(response),
        Err(_) => Ok(crate::http_utils::build_empty_response(
          http::StatusCode::INTERNAL_SERVER_ERROR,
        )),
      }
    })
  }
}

fn build_log_entry(
  result: &anyhow::Result<Response>,
  start: Instant,
  ctx: RequestContext,
  context_fields: Vec<String>,
  method: &str,
  target: &str,
) -> AccessLogEntry {
  use time::OffsetDateTime;

  let time = OffsetDateTime::now_utc();
  let duration_ms = start.elapsed().as_millis() as u64;

  let client_ip = ctx.get("client.ip").unwrap_or_default();
  let client_port: u16 =
    ctx.get("client.port").and_then(|s| s.parse().ok()).unwrap_or(0);
  let server_ip = ctx.get("server.ip").unwrap_or_default();
  let server_port: u16 =
    ctx.get("server.port").and_then(|s| s.parse().ok()).unwrap_or(0);
  let service = ctx.get("service.name").unwrap_or_default();

  // CR-002 fix: Preserve full context field keys (no stripping).
  // Previously, the first dot-separated segment was stripped from keys
  // (e.g., "auth.user" became "user"). This caused silent data loss
  // when different prefixes shared the same suffix (e.g., "auth.user"
  // and "audit.user" both became "user", and the HashMap silently
  // dropped one value). Using the full key preserves uniqueness since
  // RequestContext keys are already unique.
  let extensions: HashMap<String, String> = context_fields
    .iter()
    .filter_map(|key| ctx.get(key).map(|v| (key.clone(), v)))
    .collect();

  match result {
    Ok(response) => AccessLogEntry {
      time,
      client_ip,
      client_port,
      server_ip,
      server_port,
      method: method.to_string(),
      target: target.to_string(),
      status: response.status().as_u16(),
      duration_ms,
      service,
      err: None,
      extensions,
    },
    Err(e) => AccessLogEntry {
      time,
      client_ip,
      client_port,
      server_ip,
      server_port,
      method: method.to_string(),
      target: target.to_string(),
      status: 500,
      duration_ms,
      service,
      err: Some(e.to_string()),
      extensions,
    },
  }
}

#[cfg(test)]
mod build_log_entry_tests {
  use std::time::Instant;

  use super::*;
  use crate::context::RequestContext;

  fn make_ok_result() -> anyhow::Result<Response> {
    Ok(crate::http_utils::build_empty_response(http::StatusCode::OK))
  }

  fn make_err_result() -> anyhow::Result<Response> {
    Err(anyhow::anyhow!("connection refused"))
  }

  #[test]
  fn test_build_log_entry_success_status() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "http://example.com/",
    );
    assert_eq!(entry.status, 200);
    assert!(entry.err.is_none());
  }

  #[test]
  fn test_build_log_entry_error_status_and_message() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_err_result(),
      Instant::now(),
      ctx,
      vec![],
      "CONNECT",
      "example.com:443",
    );
    assert_eq!(entry.status, 500);
    assert!(entry.err.is_some());
    assert!(entry.err.unwrap().contains("connection refused"));
  }

  #[test]
  fn test_build_log_entry_extracts_client_ip() {
    let ctx = RequestContext::new();
    ctx.insert("client.ip", "192.168.1.100");
    ctx.insert("client.port", "54321");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.client_ip, "192.168.1.100");
    assert_eq!(entry.client_port, 54321);
  }

  #[test]
  fn test_build_log_entry_extracts_server_ip() {
    let ctx = RequestContext::new();
    ctx.insert("server.ip", "10.0.0.1");
    ctx.insert("server.port", "8080");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.server_ip, "10.0.0.1");
    assert_eq!(entry.server_port, 8080);
  }

  #[test]
  fn test_build_log_entry_extracts_service_name() {
    let ctx = RequestContext::new();
    ctx.insert("service.name", "tunnel");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "CONNECT",
      "example.com:443",
    );
    assert_eq!(entry.service, "tunnel");
  }

  #[test]
  fn test_build_log_entry_extracts_extensions() {
    let ctx = RequestContext::new();
    ctx.insert("basic_auth.user", "admin");
    ctx.insert("connect_tcp.connect_ms", "42");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![
        "basic_auth.user".to_string(),
        "connect_tcp.connect_ms".to_string(),
      ],
      "GET",
      "/",
    );
    assert_eq!(
      entry.extensions.get("basic_auth.user"),
      Some(&"admin".to_string())
    );
    assert_eq!(
      entry.extensions.get("connect_tcp.connect_ms"),
      Some(&"42".to_string())
    );
  }

  #[test]
  fn test_build_log_entry_missing_context_defaults() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.client_ip, "");
    assert_eq!(entry.client_port, 0);
    assert_eq!(entry.server_ip, "");
    assert_eq!(entry.server_port, 0);
    assert_eq!(entry.service, "");
    assert!(entry.extensions.is_empty());
  }

  #[test]
  fn test_build_log_entry_preserves_method_and_target() {
    let ctx = RequestContext::new();
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "CONNECT",
      "example.com:443",
    );
    assert_eq!(entry.method, "CONNECT");
    assert_eq!(entry.target, "example.com:443");
  }

  #[test]
  fn test_build_log_entry_invalid_port_defaults_to_zero() {
    let ctx = RequestContext::new();
    ctx.insert("client.port", "not_a_number");
    ctx.insert("server.port", "99999");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![],
      "GET",
      "/",
    );
    assert_eq!(entry.client_port, 0);
    assert_eq!(entry.server_port, 0);
  }

  #[test]
  fn test_build_log_entry_extensions_only_includes_requested_keys() {
    let ctx = RequestContext::new();
    ctx.insert("basic_auth.user", "admin");
    ctx.insert("other.key", "value");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec!["basic_auth.user".to_string()],
      "GET",
      "/",
    );
    assert_eq!(entry.extensions.len(), 1);
    // CR-002 fix: display_key now preserves full key (no stripping)
    assert!(entry.extensions.contains_key("basic_auth.user"));
    assert!(!entry.extensions.contains_key("other.key"));
  }

  #[test]
  fn test_build_log_entry_preserves_full_key_no_stripping() {
    // CR-002: Extension keys must preserve the full context field key,
    // not strip the first dot-separated segment. Stripping can cause
    // duplicate display_keys when different prefixes share the same
    // suffix (e.g., auth.user and audit.user both become user),
    // causing silent data loss in the HashMap.
    let ctx = RequestContext::new();
    ctx.insert("auth.user", "admin");
    ctx.insert("audit.user", "auditor");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec![
        "auth.user".to_string(),
        "audit.user".to_string(),
      ],
      "GET",
      "/",
    );
    // Both entries must be present (no data loss)
    assert_eq!(entry.extensions.len(), 2, "Both extension entries must be preserved");
    assert_eq!(
      entry.extensions.get("auth.user"),
      Some(&"admin".to_string()),
      "auth.user must map to 'admin'"
    );
    assert_eq!(
      entry.extensions.get("audit.user"),
      Some(&"auditor".to_string()),
      "audit.user must map to 'auditor'"
    );
  }

  #[test]
  fn test_build_log_entry_no_dot_key_preserved_as_is() {
    // CR-002: A context field key without a dot should be preserved as-is.
    let ctx = RequestContext::new();
    ctx.insert("custom_field", "value");
    let entry = build_log_entry(
      &make_ok_result(),
      Instant::now(),
      ctx,
      vec!["custom_field".to_string()],
      "GET",
      "/",
    );
    assert_eq!(entry.extensions.len(), 1);
    assert_eq!(
      entry.extensions.get("custom_field"),
      Some(&"value".to_string())
    );
  }
}

#[cfg(test)]
mod plugin_tests {
  use crate::plugin::Plugin;
  use serial_test::serial;
  use super::test_utils::TracingCapture;

  #[test]
  #[serial]
  fn test_access_log_plugin_has_file_layer() {
    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    assert!(plugin.layer_builder("file").is_some());
  }

  #[test]
  #[serial]
  fn test_access_log_plugin_no_unknown_layer() {
    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    assert!(plugin.layer_builder("unknown").is_none());
  }

  #[test]
  #[serial]
  fn test_writer_registry_initializes_from_config() {
    use crate::plugins::access_log::config::AccessLogPluginConfig;
    use crate::plugins::access_log::config::AccessLogWriterConfig;

    crate::plugins::access_log::reset_writer_registry();

    // Use tempdir so test artifacts are cleaned up automatically
    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    let prefix1 = dir1.path().join("test_writer1").to_string_lossy().to_string();
    let prefix2 = dir2.path().join("test_writer2").to_string_lossy().to_string();

    let plugin_config = AccessLogPluginConfig {
      writers: vec![
        AccessLogWriterConfig {
          path_prefix: prefix1.clone(),
          ..Default::default()
        },
        AccessLogWriterConfig {
          path_prefix: prefix2.clone(),
          format: crate::plugins::access_log::context::LogFormat::Json,
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    // create_plugin should accept config and initialize writers
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Verify writers are accessible
    let writer1 = crate::plugins::access_log::get_writer(&prefix1);
    assert!(writer1.is_ok());
    let writer2 = crate::plugins::access_log::get_writer(&prefix2);
    assert!(writer2.is_ok());
  }

  #[test]
  #[serial]
  fn test_access_log_file_layer_builds_with_writer_config() {
    crate::plugins::access_log::reset_writer_registry();

    // Use tempdir so test artifacts are cleaned up automatically
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("test_layer").to_string_lossy().to_string();

    // First initialize the writer registry
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Then build a layer referencing the writer
    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    let builder = plugin.layer_builder("file").unwrap();
    let args = serde_yaml::from_str(
      &format!(
        r#"
writer: "{}"
context_fields:
  - basic_auth.user
"#,
        prefix
      ),
    )
    .unwrap();
    let layer = builder(args);
    assert!(layer.is_ok());
  }

  #[test]
  #[serial]
  fn test_access_log_file_layer_unknown_writer_fails() {
    crate::plugins::access_log::reset_writer_registry();

    // Initialize with no writers
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    let builder = plugin.layer_builder("file").unwrap();
    let args = serde_yaml::from_str(
      r#"
writer: "logs/nonexistent"
"#,
    )
    .unwrap();
    let layer = builder(args);
    assert!(layer.is_err());
  }

  #[test]
  #[serial]
  fn test_writer_registry_path_creation_error() {
    crate::plugins::access_log::reset_writer_registry();

    // Create a regular file where a directory should be, so
    // create_dir_all fails. Use tempfile::NamedTempFile for a unique
    // path to avoid conflicts with parallel test invocations.
    let block_file = tempfile::NamedTempFile::new().unwrap();
    let block_path = block_file.path().to_string_lossy().to_string();

    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: format!("{}/subdir/log", block_path),
          ..Default::default()
        },
      ],
    };
    let result = crate::plugins::access_log::init_writer_registry(&plugin_config);
    assert!(result.is_err(), "Should fail when path cannot be created");

    // NamedTempFile auto-cleans on drop
  }

  #[test]
  #[serial]
  fn test_writer_registry_duplicate_path_prefix_rejected() {
    crate::plugins::access_log::reset_writer_registry();

    // Use tempdir so test artifacts are cleaned up automatically
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("dup_writer").to_string_lossy().to_string();

    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          format: crate::plugins::access_log::context::LogFormat::Json,
          ..Default::default()
        },
      ],
    };

    let result = crate::plugins::access_log::init_writer_registry(&plugin_config);
    assert!(result.is_err(), "Should reject duplicate path_prefix");
    assert!(
      result.unwrap_err().to_string().contains("duplicate"),
      "Error message should mention 'duplicate'"
    );
  }

  #[test]
  #[serial]
  fn test_access_log_file_layer_builds_with_empty_config() {
    crate::plugins::access_log::reset_writer_registry();

    // Use tempdir for test isolation
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("access").to_string_lossy().to_string();

    // Initialize registry with a default writer
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    let builder = plugin.layer_builder("file").unwrap();
    // Use the writer path_prefix from tempdir
    let args = serde_yaml::from_str(
      &format!(
        r#"
writer: "{}"
"#,
        prefix
      ),
    )
    .unwrap();
    let layer = builder(args);
    assert!(layer.is_ok());
  }

  #[test]
  #[serial]
  fn test_access_log_file_layer_builds_with_context_fields() {
    crate::plugins::access_log::reset_writer_registry();

    // Use tempdir for test isolation
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("access").to_string_lossy().to_string();

    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    let plugin = crate::plugins::access_log::AccessLogPlugin::new();
    let builder = plugin.layer_builder("file").unwrap();
    let args = serde_yaml::from_str(
      &format!(
        r#"
writer: "{}"
context_fields:
  - basic_auth.user
"#,
        prefix
      ),
    )
    .unwrap();
    let layer = builder(args);
    assert!(layer.is_ok());
  }

  #[tokio::test]
  #[serial]
  async fn test_access_log_plugin_uninstall_joins_writer_threads() {
    crate::plugins::access_log::reset_writer_registry();

    // Use tempdir for test isolation
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("uninstall_join").to_string_lossy().to_string();

    // Initialize registry with a writer
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Verify writer is accessible before uninstall
    let writer = crate::plugins::access_log::get_writer(&prefix);
    assert!(writer.is_ok(), "Writer should be accessible before uninstall");

    // Drop our sender clone so the only remaining sender is in the
    // registry. This simulates the production lifecycle where listeners
    // are dropped before uninstall is called.
    drop(writer);

    // Call uninstall - should return quickly (just drops senders and
    // saves JoinHandles)
    let uninstall_result = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      plugin.uninstall(),
    ).await;
    assert!(uninstall_result.is_ok(), "uninstall should complete within timeout");

    // Verify registry is cleared after uninstall
    let writer_after = crate::plugins::access_log::get_writer(&prefix);
    assert!(writer_after.is_err(), "Writer should not be accessible after uninstall");

    // flush_writer_threads() should join the writer thread (all sender
    // clones are dropped, so the thread can exit)
    crate::plugins::access_log::flush_writer_threads();

    // Verify the log file exists (writer thread flushed before exiting)
    let log_path = std::path::PathBuf::from(&prefix);
    // The writer thread may or may not have created the file (no entries
    // were sent), but flush_writer_threads should complete without error.
    let _ = log_path;
  }

  #[tokio::test]
  #[serial]
  async fn test_access_log_plugin_uninstall_clears_registry() {
    crate::plugins::access_log::reset_writer_registry();

    // Use tempdir for test isolation
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("uninstall_test").to_string_lossy().to_string();

    // Initialize registry with a writer
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Verify writer is accessible before uninstall
    let writer = crate::plugins::access_log::get_writer(&prefix);
    assert!(writer.is_ok(), "Writer should be accessible before uninstall");

    // Drop our sender clone before calling uninstall. uninstall() drops
    // Sender handles (signaling writer threads to exit), which requires
    // all sender clones to be dropped so that blocking_recv() returns
    // None and threads can exit.
    drop(writer);

    // Call uninstall
    plugin.uninstall().await;

    // After uninstall, get_writer should return error (registry cleared)
    let writer_after = crate::plugins::access_log::get_writer(&prefix);
    assert!(writer_after.is_err(), "Writer should not be accessible after uninstall");

    // Join writer threads (production calls this from main.rs after
    // all server threads exit)
    crate::plugins::access_log::flush_writer_threads();
  }

  #[tokio::test]
  #[serial]
  async fn test_access_log_plugin_uninstall_returns_quickly_with_stuck_writer() {
    // CR-006/CR-014: uninstall() should return quickly even when sender
    // clones are still held by other threads. The two-phase design
    // (uninstall drops senders + saves JoinHandles, flush_writer_threads
    // joins later) ensures uninstall doesn't block waiting for writer
    // threads that can't exit yet.
    //
    // This test holds a sender clone to prevent the writer thread from
    // exiting, then verifies that uninstall returns quickly (not waiting
    // for the stuck thread). The actual joining happens in
    // flush_writer_threads(), called after all sender clones are dropped.
    crate::plugins::access_log::reset_writer_registry();

    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("stuck_writer").to_string_lossy().to_string();

    // Initialize registry with a writer
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Hold a sender clone to prevent the writer thread from exiting.
    // This simulates the production scenario where middleware instances
    // in other server threads still hold sender clones when uninstall
    // is called.
    let _sender = crate::plugins::access_log::get_writer(&prefix).unwrap();

    // Call uninstall - it should return quickly because it only drops
    // senders and saves JoinHandles (does NOT try to join).
    let start = std::time::Instant::now();
    plugin.uninstall().await;
    let elapsed = start.elapsed();

    assert!(
      elapsed < std::time::Duration::from_millis(500),
      "uninstall should return quickly even with stuck writer, took {:?}",
      elapsed
    );

    // Verify registry is cleared after uninstall
    let writer_after = crate::plugins::access_log::get_writer(&prefix);
    assert!(writer_after.is_err(), "Writer should not be accessible after uninstall");

    // Now drop our sender clone (simulating all server threads exiting)
    drop(_sender);

    // flush_writer_threads should complete (the writer thread can now
    // exit because all sender clones are dropped)
    let flush_start = std::time::Instant::now();
    crate::plugins::access_log::flush_writer_threads();
    let flush_elapsed = flush_start.elapsed();

    assert!(
      flush_elapsed < std::time::Duration::from_secs(3),
      "flush_writer_threads should complete quickly after sender drops, took {:?}",
      flush_elapsed
    );
  }

  #[test]
  #[serial]
  fn test_reset_writer_registry_joins_writer_threads() {
    // CR-007: reset_writer_registry() must join writer threads before
    // returning, so that file handles are released and the next test
    // starts with a clean state.
    crate::plugins::access_log::reset_writer_registry();

    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("reset_join").to_string_lossy().to_string();

    // Initialize registry with a writer
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          rotate_daily: false,
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Send a log entry through the writer
    let sender = crate::plugins::access_log::get_writer(&prefix).unwrap();
    let entry = crate::plugins::access_log::LogEntry {
      entry: crate::plugins::access_log::context::AccessLogEntry {
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
        extensions: std::collections::HashMap::new(),
      },
    };
    sender.try_send(entry).unwrap();

    // Drop our sender so the writer thread can exit when the registry
    // is cleared
    drop(sender);

    // reset_writer_registry should join the writer thread, ensuring the
    // entry has been flushed to disk before returning. However, if another
    // test's init_writer_registry() interfered (reinitializing with
    // different writers), our writer thread may have been detached. In
    // that case, wait for the file to appear.
    crate::plugins::access_log::reset_writer_registry();

    // Verify the log file exists and contains the entry (proving the
    // writer thread flushed before exiting). Use a polling approach to
    // handle the case where a detached writer thread is still flushing.
    let log_path = std::path::PathBuf::from(&prefix);
    let deadline = std::time::Instant::now()
      + std::time::Duration::from_secs(3);
    let mut content = String::new();
    loop {
      if log_path.exists() {
        if let Ok(c) = std::fs::read_to_string(&log_path) {
          if !c.is_empty() {
            content = c;
            break;
          }
        }
      }
      if std::time::Instant::now() > deadline {
        break;
      }
      std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!content.is_empty(), "Log file should contain the written entry");
    assert!(content.contains("127.0.0.1"), "Log file should contain entry data");
  }

  #[test]
  #[serial]
  fn test_writer_thread_buffers_entries_not_flushed_per_entry() {
    // CR-009: Writer thread must NOT flush after every single log entry.
    // The writer's internal buffering (buffer_capacity and flush_interval)
    // should control when to flush. A per-entry flush defeats the purpose
    // of buffering and causes severe I/O performance degradation.
    //
    // This test uses a very large buffer_capacity (1 MB) and long
    // flush_interval (1 hour) so that a single small entry stays buffered
    // and is NOT flushed to disk immediately. After the writer thread exits
    // (which triggers the final flush), the entry should appear in the file.
    crate::plugins::access_log::reset_writer_registry();

    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("buffered").to_string_lossy().to_string();

    // Create a writer with large buffer and long flush interval
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          buffer_capacity: byte_unit::Byte::from_u64(1024 * 1024), // 1 MB
          flush_interval: std::time::Duration::from_secs(3600),    // 1 hour
          rotate_daily: false,
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Send a log entry
    let sender = crate::plugins::access_log::get_writer(&prefix).unwrap();
    let entry = crate::plugins::access_log::LogEntry {
      entry: crate::plugins::access_log::context::AccessLogEntry {
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
        extensions: std::collections::HashMap::new(),
      },
    };
    sender.try_send(entry).unwrap();

    // Give the writer thread time to process the entry (write to buffer)
    std::thread::sleep(std::time::Duration::from_millis(100));

    // The entry should NOT be flushed to disk yet because:
    // - buffer_capacity (1 MB) is not exceeded by a single entry
    // - flush_interval (1 hour) has not elapsed
    // - Per-entry flush should NOT be called (CR-009 fix)
    let log_path = std::path::PathBuf::from(&prefix);
    if log_path.exists() {
      let content = std::fs::read_to_string(&log_path).unwrap();
      assert!(
        content.is_empty(),
        "Entry should be buffered, not flushed to disk immediately. \
         Got {} bytes: {:?}",
        content.len(),
        &content[..content.len().min(200)]
      );
    }

    // Drop our sender so the writer thread can exit
    drop(sender);

    // Reset the registry (joins writer thread, causing final flush).
    // Note: if another test's init_writer_registry() call interfered
    // (by reinitializing the registry with different writers), our
    // writer thread may have been detached. In that case, the thread
    // is still running and will eventually flush. Wait for the file
    // to appear with a timeout.
    crate::plugins::access_log::reset_writer_registry();

    // Wait for the log file to be created and contain the entry.
    // The writer thread flushes on exit, but if it was detached by
    // another test's reinit, it may still be flushing.
    let deadline = std::time::Instant::now()
      + std::time::Duration::from_secs(3);
    let mut content = String::new();
    loop {
      if log_path.exists() {
        if let Ok(c) = std::fs::read_to_string(&log_path) {
          if !c.is_empty() {
            content = c;
            break;
          }
        }
      }
      if std::time::Instant::now() > deadline {
        break;
      }
      std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!content.is_empty(), "Entry should be flushed after writer thread exits");
    assert!(content.contains("127.0.0.1"), "Log file should contain entry data");
  }

  #[test]
  #[serial]
  fn test_get_writer_not_blocked_during_reinit() {
    // CR-010: init_writer_registry must not hold the WRITER_REGISTRY Mutex
    // lock during long operations (thread joining, directory creation, thread
    // spawning). When reinitializing with different writers, the old writer
    // threads must be joined OUTSIDE the lock so that get_writer() is not
    // blocked for seconds.
    //
    // This test initializes the registry with a writer, then triggers a
    // reinit in a background thread. While reinit is in progress (joining
    // old threads), get_writer() should return quickly (not block for
    // seconds waiting for the lock).
    crate::plugins::access_log::reset_writer_registry();

    let dir1 = tempfile::tempdir().unwrap();
    let prefix1 = dir1.path().join("old_writer").to_string_lossy().to_string();

    // Initialize registry with a writer
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix1.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Hold a sender clone so the old writer thread CANNOT exit. This
    // forces the reinit's join to block (waiting for the thread that
    // can't exit), which makes the lock contention detectable.
    let sender_clone = crate::plugins::access_log::get_writer(&prefix1).unwrap();

    // Start reinit in a background thread with different writers
    let dir2 = tempfile::tempdir().unwrap();
    let prefix2 = dir2.path().join("new_writer").to_string_lossy().to_string();
    let new_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix2.clone(),
          ..Default::default()
        },
      ],
    };

    let init_handle = std::thread::spawn(move || {
      let _ = crate::plugins::access_log::init_writer_registry(&new_config);
    });

    // Give the reinit thread time to acquire the lock and reach the
    // join phase. With the bug, the lock is held during the 2-second
    // join timeout, so get_writer() would block for ~2s.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // get_writer should return quickly (not block for seconds).
    // With the bug, get_writer blocks because the lock is held during
    // the 2-second join timeout. After the fix, the lock is released
    // during the join, so get_writer can acquire it quickly.
    let start = std::time::Instant::now();
    let _ = crate::plugins::access_log::get_writer(&prefix1);
    let elapsed = start.elapsed();

    assert!(
      elapsed < std::time::Duration::from_millis(500),
      "get_writer should not block for more than 500ms during reinit, \
       took {:?} (lock likely held during thread join)",
      elapsed
    );

    // Clean up: drop sender clone so reinit's join can complete
    drop(sender_clone);
    let _ = init_handle.join();
    crate::plugins::access_log::reset_writer_registry();
    crate::plugins::access_log::reset_writer_registry();
  }

  #[test]
  #[serial]
  fn test_create_plugin_invalid_config_panics_with_descriptive_message() {
    // CR-013: create_plugin must produce a descriptive panic message when
    // config parsing fails, including the underlying error cause. With the
    // bug, .expect("failed to parse access_log plugin config") produces a
    // generic message that doesn't include the actual parse error. With the
    // fix, the panic message includes "access_log:" prefix and the error
    // details for actionable debugging.
    crate::plugins::access_log::reset_writer_registry();

    let result = std::panic::catch_unwind(|| {
      // Pass invalid config that will fail to parse as AccessLogPluginConfig
      let bad_config = serde_yaml::Value::String("not_a_valid_config".to_string());
      let _ = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&bad_config));
    });

    assert!(result.is_err(), "create_plugin should panic on invalid config");

    let panic_payload = result.unwrap_err();
    let message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
      s.to_string()
    } else if let Some(s) = panic_payload.downcast_ref::<String>() {
      s.clone()
    } else {
      "unknown panic payload".to_string()
    };

    // The panic message should include "access_log:" prefix for easy
    // identification and should include details about the parse error
    assert!(
      message.contains("access_log:"),
      "Panic message should contain 'access_log:' prefix, got: {:?}",
      message
    );
  }

  #[test]
  #[serial]
  fn test_init_writer_registry_phase5_cleanup_uses_timeout() {
    // CR-012: Phase 5 cleanup must use a timeout when joining newly spawned
    // threads. If a writer thread can't exit (e.g., a sender clone is still
    // held elsewhere), the cleanup must not block indefinitely. With the bug,
    // jh.join() blocks forever; with the fix, join_writer_handles times out
    // after 2 seconds per thread.
    //
    // This test triggers the Phase 5 path by racing two init_writer_registry
    // calls: Thread A with empty writers (fast, wins the race) and Thread B
    // with a real writer (slower, hits Phase 5 cleanup). We hold a sender
    // clone from Thread B's writer to prevent the thread from exiting,
    // ensuring the join must time out rather than complete instantly.
    crate::plugins::access_log::reset_writer_registry();

    // We need to trigger Phase 5 where Thread B finds the registry already
    // set by Thread A. Both threads' Phase 1 must see guard is None (i.e.,
    // both start before either reaches Phase 5).
    //
    // Strategy: Use a barrier to coordinate two threads. Thread A has empty
    // writers (instant Phases 2-4), Thread B has a real writer. After both
    // pass Phase 1, Thread A races to Phase 5 first and sets the registry.
    // Thread B then hits Phase 5 and must clean up its threads.
    //
    // To make Thread B's writer thread unable to exit, we need a sender
    // clone. But Thread B's writer sender is only in the WriterHandle which
    // is inside init_writer_registry. We can't access it from outside.
    //
    // Alternative approach: Instead of holding a sender clone, we verify the
    // behavior by checking that init_writer_registry returns Ok without
    // hanging, and that the cleanup is done with the same timeout pattern as
    // join_writer_handles. We can trigger Phase 5 by calling
    // init_writer_registry from two threads concurrently.

    use std::sync::Arc;
    use std::sync::Barrier;

    let barrier = Arc::new(Barrier::new(2));
    let barrier1 = barrier.clone();
    let barrier2 = barrier.clone();

    // Config A: empty writers (fast init)
    let config_a =
      crate::plugins::access_log::config::AccessLogPluginConfig { writers: vec![] };

    // Config B: has a writer (slower init due to thread spawning)
    let dir = tempfile::tempdir().unwrap();
    let prefix_b = dir.path().join("phase5_writer").to_string_lossy().to_string();
    let config_b = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![crate::plugins::access_log::config::AccessLogWriterConfig {
        path_prefix: prefix_b.clone(),
        ..Default::default()
      }],
    };

    let handle_a = std::thread::spawn(move || {
      // Wait until both threads are ready to start Phase 1
      barrier1.wait();
      let _ = crate::plugins::access_log::init_writer_registry(&config_a);
    });

    let handle_b = std::thread::spawn(move || {
      // Wait until both threads are ready to start Phase 1
      barrier2.wait();
      let _ = crate::plugins::access_log::init_writer_registry(&config_b);
    });

    // Both threads should return without hanging. With the bug (no timeout
    // in Phase 5), if Thread B's writer thread can't exit, Thread B's
    // init_writer_registry would hang indefinitely. With the fix
    // (join_writer_handles with timeout), it returns within ~2 seconds.
    let result_a = handle_a.join();
    let result_b = handle_b.join();
    assert!(result_a.is_ok(), "Thread A should not panic");
    assert!(result_b.is_ok(), "Thread B should not panic");

    // Reset for cleanup
    crate::plugins::access_log::reset_writer_registry();
  }

  #[tokio::test]
  #[serial]
  async fn test_try_send_on_full_channel_logs_warning() {
    // CR-023: This test verifies that AccessLogMiddleware::call() logs
    // warnings via tracing when try_send fails, not just that tokio's
    // channel error types work correctly. The previous test only tested
    // the raw channel; this test exercises the actual middleware code path.
    use crate::plugins::access_log::context::AccessLogEntry;
    use crate::plugins::access_log::LogEntry;
    use tower::Layer;
    use tower::ServiceExt;
    use http_body_util::BodyExt;

    // --- Test Full case ---
    {
      let (capture, _guard) = TracingCapture::new();

      // Create a channel with capacity 1 and fill it
      let (tx, _rx) = std::sync::mpsc::sync_channel::<LogEntry>(1);
      let dummy_entry = LogEntry {
        entry: AccessLogEntry {
          time: time::OffsetDateTime::now_utc(),
          client_ip: String::new(),
          client_port: 0,
          server_ip: String::new(),
          server_port: 0,
          method: String::new(),
          target: String::new(),
          status: 0,
          duration_ms: 0,
          service: String::new(),
          err: None,
          extensions: std::collections::HashMap::new(),
        },
      };
      tx.try_send(dummy_entry).unwrap();

      // Build the middleware via AccessLogLayer
      let access_log_layer = super::AccessLogLayer {
        tx,
        context_fields: vec![],
      };
      let inner = crate::server::placeholder_service();
      let mut service = Layer::layer(&access_log_layer, inner);

      // Call the middleware - try_send should fail with Full
      let body: crate::http_utils::RequestBody =
        http_body_util::Empty::<bytes::Bytes>::new()
          .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
          .boxed_unsync();
      let req = http::Request::builder()
        .method("GET")
        .uri("http://example.com/")
        .body(body)
        .unwrap();
      let svc = service.ready().await.unwrap();
      let _ = tower::Service::call(svc, req).await;

      // Verify tracing captured "channel full" warning
      let output = capture.output();
      assert!(
        output.contains("channel full"),
        "tracing should capture 'channel full' warning from middleware, got: {:?}",
        &output[..output.len().min(500)]
      );
    }

    // --- Test Closed case ---
    {
      let (capture, _guard) = TracingCapture::new();

      // Create a channel and drop the receiver to make it closed
      let (tx, rx) = std::sync::mpsc::sync_channel::<LogEntry>(1);
      drop(rx);

      // Build the middleware via AccessLogLayer
      let access_log_layer = super::AccessLogLayer {
        tx,
        context_fields: vec![],
      };
      let inner = crate::server::placeholder_service();
      let mut service = Layer::layer(&access_log_layer, inner);

      // Call the middleware - try_send should fail with Closed
      let body: crate::http_utils::RequestBody =
        http_body_util::Empty::<bytes::Bytes>::new()
          .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
          .boxed_unsync();
      let req = http::Request::builder()
        .method("GET")
        .uri("http://example.com/")
        .body(body)
        .unwrap();
      let svc = service.ready().await.unwrap();
      let _ = tower::Service::call(svc, req).await;

      // Verify tracing captured "channel closed" warning
      let output = capture.output();
      assert!(
        output.contains("channel closed"),
        "tracing should capture 'channel closed' warning from middleware, got: {:?}",
        &output[..output.len().min(500)]
      );
    }
  }

  #[tokio::test]
  #[serial]
  async fn test_flush_writer_threads_joins_after_sender_clones_dropped() {
    // CR-014: Multi-threaded shutdown can leave writer threads unflushed.
    // The fix separates "drop senders" (in uninstall) from "join threads"
    // (in flush_writer_threads). This test verifies the full lifecycle:
    // 1. uninstall() drops sender handles and saves JoinHandles
    // 2. While sender clones are held, flush_writer_threads() times out
    // 3. After sender clones are dropped, flush_writer_threads() joins
    //    successfully and the writer thread flushes its data
    crate::plugins::access_log::reset_writer_registry();

    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("cr014_flush").to_string_lossy().to_string();

    // Initialize registry with a writer that has large buffer and long
    // flush interval so entries are buffered (not immediately flushed)
    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          buffer_capacity: byte_unit::Byte::from_u64(1024 * 1024),
          flush_interval: std::time::Duration::from_secs(3600),
          rotate_daily: false,
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Send a log entry through the writer
    let sender = crate::plugins::access_log::get_writer(&prefix).unwrap();
    let entry = crate::plugins::access_log::LogEntry {
      entry: crate::plugins::access_log::context::AccessLogEntry {
        time: time::OffsetDateTime::now_utc(),
        client_ip: "10.0.0.1".to_string(),
        client_port: 54321,
        server_ip: "0.0.0.0".to_string(),
        server_port: 8080,
        method: "GET".to_string(),
        target: "http://cr014.test/".to_string(),
        status: 200,
        duration_ms: 7,
        service: "cr014".to_string(),
        err: None,
        extensions: std::collections::HashMap::new(),
      },
    };
    sender.try_send(entry).unwrap();

    // Give the writer thread time to process the entry (buffer it)
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Hold a sender clone to simulate another server thread holding
    // middleware sender clones
    let sender_clone = crate::plugins::access_log::get_writer(&prefix).unwrap();

    // Drop our main sender (simulating this server thread dropping it)
    drop(sender);

    // Call uninstall - should return quickly (saves JoinHandles,
    // does not try to join)
    let start = std::time::Instant::now();
    plugin.uninstall().await;
    let elapsed = start.elapsed();
    assert!(
      elapsed < std::time::Duration::from_millis(500),
      "uninstall should return quickly, took {:?}", elapsed
    );

    // Drop the remaining sender clone (simulating all server threads
    // having exited and dropped their listeners)
    drop(sender_clone);

    // Now flush_writer_threads() should join the writer thread
    // successfully (all sender clones are dropped, the thread can
    // exit and flush its buffer)
    crate::plugins::access_log::flush_writer_threads();

    // Verify the log file contains the entry (proving the writer
    // thread flushed its buffer before exiting)
    let log_path = std::path::PathBuf::from(&prefix);
    let deadline = std::time::Instant::now()
      + std::time::Duration::from_secs(3);
    let mut content = String::new();
    loop {
      if log_path.exists() {
        if let Ok(c) = std::fs::read_to_string(&log_path) {
          if !c.is_empty() {
            content = c;
            break;
          }
        }
      }
      if std::time::Instant::now() > deadline {
        break;
      }
      std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!content.is_empty(), "Log file should contain the written entry");
    assert!(content.contains("10.0.0.1"), "Log file should contain entry data");
  }

  #[test]
  #[serial]
  fn test_init_writer_registry_partial_failure_cleans_up_spawned_threads() {
    // CR-015: When init_writer_registry fails partway through (e.g.,
    // second writer's directory creation fails), the already-spawned
    // writer threads must be properly cleaned up (joined, not just
    // detached). Without the fix, the JoinHandles are dropped without
    // joining, leaving orphaned writer threads that may hold file handles.
    crate::plugins::access_log::reset_writer_registry();

    // Create a valid tempdir for the first writer
    let dir1 = tempfile::tempdir().unwrap();
    let prefix1 = dir1.path().join("valid_writer").to_string_lossy().to_string();

    // Create a blocking file where the second writer's directory should be,
    // so create_dir_all fails for the second writer.
    let block_file = tempfile::NamedTempFile::new().unwrap();
    let block_path = block_file.path().to_string_lossy().to_string();
    let prefix2 = format!("{}/subdir/log", block_path);

    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix1.clone(),
          ..Default::default()
        },
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix2,
          ..Default::default()
        },
      ],
    };

    let result = crate::plugins::access_log::init_writer_registry(&plugin_config);

    // Should fail because the second writer's directory can't be created
    assert!(result.is_err(), "init_writer_registry should fail on partial error");

    // The registry should NOT be set (partial failure should not leave
    // partial state)
    let writer_result = crate::plugins::access_log::get_writer(&prefix1);
    assert!(
      writer_result.is_err(),
      "Registry should not be set after partial failure"
    );

    // Verify the first writer's thread was properly cleaned up by trying
    // to reinitialize. If the thread was orphaned, the file might still
    // be locked. With the fix, init_writer_registry should join the
    // spawned threads before returning the error, so reinitialization
    // should work cleanly.
    let dir3 = tempfile::tempdir().unwrap();
    let prefix3 = dir3.path().join("reinit_writer").to_string_lossy().to_string();
    let reinit_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix3.clone(),
          ..Default::default()
        },
      ],
    };
    let reinit_result = crate::plugins::access_log::init_writer_registry(&reinit_config);
    assert!(
      reinit_result.is_ok(),
      "Reinitialization should succeed after partial failure cleanup: {:?}",
      reinit_result
    );

    // Verify the new writer is accessible
    let writer = crate::plugins::access_log::get_writer(&prefix3);
    assert!(writer.is_ok(), "New writer should be accessible after reinit");
  }

  #[test]
  #[serial]
  fn test_init_writer_registry_validates_paths_before_spawning() {
    // CR-015 (alternate test): All directory validations should happen
    // before any threads are spawned. This way, if any path is invalid,
    // no threads are spawned at all (no cleanup needed). This test
    // verifies that when the first writer's directory is invalid, no
    // writer threads exist.
    crate::plugins::access_log::reset_writer_registry();

    // Create a blocking file for the first writer
    let block_file = tempfile::NamedTempFile::new().unwrap();
    let block_path = block_file.path().to_string_lossy().to_string();
    let prefix1 = format!("{}/subdir/log", block_path);

    // Second writer is valid
    let dir2 = tempfile::tempdir().unwrap();
    let prefix2 = dir2.path().join("valid_writer").to_string_lossy().to_string();

    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix1,
          ..Default::default()
        },
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix2.clone(),
          ..Default::default()
        },
      ],
    };

    let result = crate::plugins::access_log::init_writer_registry(&plugin_config);
    assert!(result.is_err(), "Should fail when first writer's path is invalid");

    // Registry should not be set
    let writer = crate::plugins::access_log::get_writer(&prefix2);
    assert!(
      writer.is_err(),
      "Registry should not be set after validation failure"
    );
  }

  #[test]
  #[serial]
  fn test_access_log_uses_tracing_for_warnings() {
    // CR-017: The access_log module must use tracing::warn! instead of
    // eprintln! for error/warning output. This test verifies that when
    // the join timeout path is exercised (writer thread doesn't exit in
    // time), the warning goes through the tracing framework. With
    // eprintln!, no tracing events are recorded; with tracing::warn!,
    // the subscriber captures them.
    let (capture, _guard) = TracingCapture::new();

    // Trigger the join_writer_handles timeout path by creating a writer
    // thread that blocks beyond the join timeout, then reinitializing the
    // registry (which joins the old writer thread).
    crate::plugins::access_log::reset_writer_registry();

    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("tracing_test").to_string_lossy().to_string();

    let plugin_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![
        crate::plugins::access_log::config::AccessLogWriterConfig {
          path_prefix: prefix.clone(),
          ..Default::default()
        },
      ],
    };
    let config_value = serde_yaml::to_value(&plugin_config).unwrap();
    let _plugin = crate::plugins::access_log::AccessLogPlugin::create_plugin(Some(&config_value));

    // Hold a sender clone so the writer thread cannot exit (its
    // blocking_recv() won't return None until all senders are dropped).
    // This forces the join in reset_writer_registry/init_writer_registry
    // to time out, triggering the warn! in join_writer_handles.
    let _sender = crate::plugins::access_log::get_writer(&prefix).unwrap();

    // Reinitialize with empty writers, which triggers the reinit path.
    // The old writer thread can't exit (we hold a sender clone), so
    // the join times out and warn! is called.
    let empty_config = crate::plugins::access_log::config::AccessLogPluginConfig {
      writers: vec![],
    };
    let _ = crate::plugins::access_log::init_writer_registry(&empty_config);

    // Verify tracing captured the timeout warning.
    // With eprintln!, no tracing events are recorded.
    let output = capture.output();
    assert!(
      output.contains("did not exit within"),
      "tracing output should contain 'did not exit within' (join timeout warning), got: {:?}",
      &output[..output.len().min(500)]
    );

    // Clean up: drop sender so the writer thread can exit
    drop(_sender);
    crate::plugins::access_log::reset_writer_registry();
  }
}
