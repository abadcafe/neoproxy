use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use tokio::signal::unix as signal;
use tokio::{runtime, sync, task};
use tracing::{debug, error, info, warn};

use crate::cli::CmdOpt;
use crate::config::{Config, ConfigErrorCollector};

mod auth;
mod cli;
mod config;
mod context;
mod h3_stream;
mod http_message;
mod listener;
mod listeners;
mod plugin;
#[cfg(test)]
mod plugin_tests;
mod plugins;
#[cfg(test)]
mod plugins_tests;
mod server;
mod server_thread;
mod service;
mod shutdown;
mod stream;
mod tls;
mod tracker;

#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod listeners_tests;

#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod h3_stream_tests;
#[cfg(test)]
mod http_message_tests;
#[cfg(test)]
mod main_tests;
#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod server_thread_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
mod tls_tests;
#[cfg(test)]
mod tracker_tests;

/// Thread check interval for detecting server thread exit.
const THREAD_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// Configuration for the non-blocking log writer.
///
/// This struct holds configuration for the tracing_appender
/// non-blocking writer. The default `buffered_lines_limit(1)` ensures
/// logs are written immediately without buffering delay.
#[derive(Debug, Clone, Copy)]
struct LogWriterConfig {
  /// Number of lines to buffer before flushing.
  /// Set to 1 to ensure each log line is sent to the background thread
  /// immediately.
  buffered_lines_limit: usize,
}

impl Default for LogWriterConfig {
  fn default() -> Self {
    Self { buffered_lines_limit: 1 }
  }
}

impl LogWriterConfig {
  /// Build a NonBlocking writer with the configured settings.
  fn build<W>(
    &self,
    writer: W,
  ) -> (
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
  )
  where
    W: std::io::Write + Send + 'static,
  {
    tracing_appender::non_blocking::NonBlockingBuilder::default()
      .buffered_lines_limit(self.buffered_lines_limit)
      .finish(writer)
  }
}

/// Exit reason for determining the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitReason {
  /// Thread exited normally (returned Ok(())).
  Normal,
  /// Thread panicked.
  Panic,
  /// Thread exited with an error (returned Err(e)).
  Error,
}

/// Determine the exit code based on collected exit reasons.
///
/// # Exit Code Rules
/// - Empty reasons: 0 (signal-triggered normal shutdown)
/// - Contains any Panic: 1
/// - Contains any Error (no Panic): 2
/// - All Normal: 0
fn determine_exit_code(exit_reasons: &[ExitReason]) -> i32 {
  if exit_reasons.is_empty() {
    return 0;
  }

  if exit_reasons.contains(&ExitReason::Panic) {
    return 1;
  }

  if exit_reasons.contains(&ExitReason::Error) {
    return 2;
  }

  0
}

fn init_log(
  log_directory: &str,
) -> tracing_appender::non_blocking::WorkerGuard {
  let log_appender =
    tracing_appender::rolling::daily(log_directory, "neoproxy.log");

  let config = LogWriterConfig::default();
  let (writer, guard) = config.build(log_appender);

  let filter = tracing_subscriber::EnvFilter::builder()
    .with_default_directive(
      tracing_subscriber::filter::LevelFilter::INFO.into(),
    )
    .with_env_var("NEOPROXY_LOG")
    .from_env_lossy();

  tracing_subscriber::fmt()
    .with_writer(writer)
    .with_max_level(tracing::Level::TRACE)
    .with_env_filter(filter)
    .compact()
    .with_ansi(true)
    .with_file(true)
    .with_line_number(true)
    .with_thread_names(true)
    .with_level(true)
    .init();

  guard
}

/// Create a signal waiting future for SIGINT/SIGTERM.
fn create_signal_future() -> Pin<Box<dyn Future<Output = ()> + Send>> {
  Box::pin(async {
    let sigint = async {
      match signal::signal(signal::SignalKind::interrupt()) {
        Ok(mut stream) => {
          stream.recv().await;
        }
        Err(e) => {
          warn!("failed to register SIGINT handler: {e}");
          std::future::pending::<()>().await;
        }
      }
    };

    let sigterm = async {
      match signal::signal(signal::SignalKind::terminate()) {
        Ok(mut stream) => {
          stream.recv().await;
        }
        Err(e) => {
          warn!("failed to register SIGTERM handler: {e}");
          std::future::pending::<()>().await;
        }
      }
    };

    tokio::select! {
      _ = sigint => {}
      _ = sigterm => {}
    }
  })
}

/// Main loop that monitors signals and server threads.
///
/// This function implements the core shutdown logic:
/// 1. If no server threads, wait for signal and exit with code 0
/// 2. Otherwise, concurrently listen for:
///    - SIGINT/SIGTERM signals
///    - Worker thread exits (polled every 100ms)
/// 3. On signal: trigger graceful shutdown
/// 4. On server thread abnormal exit: record reason and trigger
///    shutdown
/// 5. Determine exit code based on collected exit reasons
///
/// # Returns
/// Exit code: 0 (normal), 1 (panic), 2 (error), 3 (other error)
async fn main_loop(
  handles: Vec<thread::JoinHandle<Result<()>>>,
  shutdown_notify: Arc<sync::Notify>,
  shutdown_triggered: Arc<AtomicBool>,
) -> i32 {
  main_loop_with_signal(
    handles,
    shutdown_notify,
    shutdown_triggered,
    create_signal_future(),
  )
  .await
}

/// Inner implementation of main_loop with injectable signal future.
/// This allows for easier testing by providing a custom signal source.
async fn main_loop_with_signal(
  handles: Vec<thread::JoinHandle<Result<()>>>,
  shutdown_notify: Arc<sync::Notify>,
  shutdown_triggered: Arc<AtomicBool>,
  mut signal_future: Pin<Box<dyn Future<Output = ()> + Send>>,
) -> i32 {
  // If no server threads, wait for signal and exit with code 0
  if handles.is_empty() {
    signal_future.await;
    info!("received shutdown signal, exiting (no server threads)");
    return 0;
  }

  let mut joined_indices: HashSet<usize> = HashSet::new();
  let mut exit_reasons: Vec<ExitReason> = Vec::new();
  let mut signal_received_once = false;

  // Take ownership of handles for joining
  let mut handles = handles;

  // Main loop
  loop {
    // Check for signals using tokio::select!
    // We use as_mut() to get a pinned reference that can be polled
    // multiple times
    let signal_received = if signal_received_once {
      // Signal already received, only check threads
      tokio::select! {
        _ = tokio::time::sleep(THREAD_CHECK_INTERVAL) => {
          let all_joined = check_server_threads(
            &mut handles,
            &mut joined_indices,
            &mut exit_reasons,
            &shutdown_triggered,
            &shutdown_notify,
          );

          if all_joined {
            break;
          }
          false
        }
      }
    } else {
      tokio::select! {
        // Signal branch
        _ = signal_future.as_mut() => {
          signal_received_once = true;
          true
        }
        // Thread check branch (every 100ms)
        _ = tokio::time::sleep(THREAD_CHECK_INTERVAL) => {
          let all_joined = check_server_threads(
            &mut handles,
            &mut joined_indices,
            &mut exit_reasons,
            &shutdown_triggered,
            &shutdown_notify,
          );

          if all_joined {
            break;
          }
          false
        }
      }
    };

    if signal_received {
      if !shutdown_triggered.swap(true, Ordering::SeqCst) {
        info!("received shutdown signal, initiating graceful shutdown");
        shutdown_notify.notify_waiters();
      } else {
        debug!("received shutdown signal, already shutting down");
      }
    }
  }

  // Determine exit code
  let exit_code = determine_exit_code(&exit_reasons);
  info!("shutdown complete");
  exit_code
}

/// Check server threads for exit status.
///
/// Returns true if all threads have been joined.
fn check_server_threads(
  handles: &mut [thread::JoinHandle<Result<()>>],
  joined_indices: &mut HashSet<usize>,
  exit_reasons: &mut Vec<ExitReason>,
  shutdown_triggered: &Arc<AtomicBool>,
  shutdown_notify: &Arc<sync::Notify>,
) -> bool {
  for (idx, handle) in handles.iter_mut().enumerate() {
    // Skip already joined threads
    if joined_indices.contains(&idx) {
      continue;
    }

    // Check if thread has finished (without holding a reference)
    let finished = handle.is_finished();

    if !finished {
      continue;
    }

    // Thread has finished, take ownership of the handle
    // This is safe because we only do this once per index
    let handle = std::mem::replace(handle, thread::spawn(|| Ok(())));

    // Get thread name before joining (ownership transferred)
    // We need to copy the name to avoid borrowing issues
    let thread_name =
      handle.thread().name().unwrap_or("unknown").to_string();

    match handle.join() {
      // Thread panicked
      Err(panic_payload) => {
        error!(
          "server thread '{}' panicked: {:?}",
          thread_name, panic_payload
        );
        exit_reasons.push(ExitReason::Panic);

        // Trigger shutdown if not already triggered
        if !shutdown_triggered.swap(true, Ordering::SeqCst) {
          shutdown_notify.notify_waiters();
        }
      }
      // Thread exited normally
      Ok(result) => match result {
        Ok(()) => {
          exit_reasons.push(ExitReason::Normal);
        }
        Err(e) => {
          error!(
            "server thread '{}' exited with error: {}",
            thread_name, e
          );
          exit_reasons.push(ExitReason::Error);

          // Trigger shutdown if not already triggered
          if !shutdown_triggered.swap(true, Ordering::SeqCst) {
            shutdown_notify.notify_waiters();
          }
        }
      },
    }

    joined_indices.insert(idx);
  }

  // Check if all threads have been joined
  joined_indices.len() == handles.len()
}

/// Install the rustls crypto provider based on configuration.
fn install_tls_provider(config: &Config) -> Result<()> {
  let provider_name = config.tls_provider().unwrap_or("ring");
  match provider_name {
    #[cfg(feature = "tls-openssl")]
    "openssl" => {
      rustls_openssl::default_provider().install_default().map_err(
        |_| {
          anyhow::anyhow!(
            "Failed to install rustls-openssl rustls crypto provider",
          )
        },
      )?;
      Ok(())
    }
    #[cfg(not(feature = "tls-openssl"))]
    "openssl" => {
      anyhow::bail!(
        "tls_provider 'openssl' requires the 'tls-openssl' cargo \
         feature"
      )
    }
    "ring" => {
      rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| {
          anyhow::anyhow!("Failed to install rustls crypto provider")
        })?;
      Ok(())
    }
    other => {
      anyhow::bail!(
        "Unknown tls_provider '{other}'. Supported: 'ring', 'openssl'"
      )
    }
  }
}

fn main() -> Result<()> {
  // Load config
  let config = Config::load(CmdOpt::global().config_file())?;

  // Install rustls crypto provider based on config
  install_tls_provider(&config)?;

  // Validate config
  let mut collector = ConfigErrorCollector::new();
  let listener_manager = listeners::ListenerManager::new();
  config.validate(&mut collector, &listener_manager);
  if collector.has_errors() {
    collector.report_and_exit();
  }

  // Initialize logging after config is loaded
  let _guard = init_log("logs/");

  info!("server started with config:\n{:#?}\n", &config);

  // Set global config for use by server threads
  Config::init_global(config);

  // Create shutdown signal
  let shutdown_notify = Arc::new(sync::Notify::new());
  let shutdown_triggered = Arc::new(AtomicBool::new(false));

  // Spawn server threads (each builds its own PluginManager and
  // listeners)
  let handles: Vec<thread::JoinHandle<Result<()>>> = (0
    ..Config::global().server_threads())
    .map(|i| {
      let shutdown = shutdown_notify.clone();
      thread::Builder::new()
        .name(format!("neoproxy-server-{}", i))
        .spawn(move || server_thread::run_server_thread(shutdown, i))
        .unwrap()
    })
    .collect();

  // Main loop (all async work inside rt.block_on)
  let local_set = task::LocalSet::new();
  let rt = runtime::Builder::new_current_thread()
    .enable_all()
    .thread_name("neoproxy main thread")
    .build()?;

  let exit_code = rt.block_on(local_set.run_until(main_loop(
    handles,
    shutdown_notify,
    shutdown_triggered,
  )));

  // Writer threads are now joined directly in uninstall(), no need
  // for separate flush.

  std::process::exit(exit_code);
}
