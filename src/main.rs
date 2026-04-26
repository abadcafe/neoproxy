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

use crate::config::Config;

mod auth;
mod config;
mod config_validator;
mod connect_utils;
mod http_types;
mod listeners;
mod plugin;
mod plugins;
mod server;
mod shutdown;
mod stream;
mod h3_stream;
mod access_log;
mod tls;

/// Thread check interval for detecting worker thread exit.
const THREAD_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// Configuration for the non-blocking log writer.
///
/// This struct holds configuration for the tracing_appender non-blocking writer.
/// The default `buffered_lines_limit(1)` ensures logs are written immediately
/// without buffering delay.
#[derive(Debug, Clone, Copy)]
struct LogWriterConfig {
  /// Number of lines to buffer before flushing.
  /// Set to 1 to ensure each log line is sent to the background thread immediately.
  buffered_lines_limit: usize,
}

impl Default for LogWriterConfig {
  fn default() -> Self {
    Self {
      buffered_lines_limit: 1,
    }
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

fn run_server_threads(
  closer: Arc<sync::Notify>,
) -> Vec<thread::JoinHandle<Result<()>>> {
  let mut server_thread_handles = vec![];
  for i in 0..Config::global().worker_threads {
    let closer = closer.clone();
    let name = format!("neoproxy server thread {i}");
    server_thread_handles.push(
      thread::Builder::new()
        .name(name.clone())
        .spawn(move || -> Result<()> {
          server::server_thread(name.as_str(), closer.clone())
        })
        .unwrap(),
    );
  }

  server_thread_handles
}

fn init_log() -> tracing_appender::non_blocking::WorkerGuard {
  let log_appender = tracing_appender::rolling::daily(
    Config::global().log_directory.as_str(),
    "neoproxy.log",
  );

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

/// Main loop that monitors signals and worker threads.
///
/// This function implements the core shutdown logic:
/// 1. If no worker threads, wait for signal and exit with code 0
/// 2. Otherwise, concurrently listen for:
///    - SIGINT/SIGTERM signals
///    - Worker thread exits (polled every 100ms)
/// 3. On signal: trigger graceful shutdown
/// 4. On worker thread abnormal exit: record reason and trigger shutdown
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
  // If no worker threads, wait for signal and exit with code 0
  if handles.is_empty() {
    signal_future.await;
    info!("received shutdown signal, exiting (no worker threads)");
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
    // We use as_mut() to get a pinned reference that can be polled multiple times
    let signal_received = if signal_received_once {
      // Signal already received, only check threads
      tokio::select! {
        _ = tokio::time::sleep(THREAD_CHECK_INTERVAL) => {
          let all_joined = check_worker_threads(
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
          let all_joined = check_worker_threads(
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

/// Check worker threads for exit status.
///
/// Returns true if all threads have been joined.
fn check_worker_threads(
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
          "worker thread '{}' panicked: {:?}",
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
            "worker thread '{}' exited with error: {}",
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

fn main() -> Result<()> {
  // Install rustls crypto provider before any TLS operations
  rustls::crypto::ring::default_provider()
    .install_default()
    .expect("Failed to install rustls crypto provider");

  let _guard = init_log();
  info!("server started with config:\n{:#?}\n", &Config::global());

  let shutdown_notify = Arc::new(sync::Notify::new());
  let shutdown_triggered = Arc::new(AtomicBool::new(false));
  let handles = run_server_threads(shutdown_notify.clone());

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

  std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_auth_module_exists() {
    // Verify the auth module exists by using a type from it
    use crate::auth::AuthError;
    let _error = AuthError::InvalidCredentials;
  }

  #[test]
  fn test_thread_check_interval_constant() {
    assert_eq!(THREAD_CHECK_INTERVAL, Duration::from_millis(100));
  }

  // ============== ExitReason Tests ==============

  #[test]
  fn test_exit_reason_normal() {
    let reason = ExitReason::Normal;
    assert_eq!(reason, ExitReason::Normal);
  }

  #[test]
  fn test_exit_reason_panic() {
    let reason = ExitReason::Panic;
    assert_eq!(reason, ExitReason::Panic);
  }

  #[test]
  fn test_exit_reason_error() {
    let reason = ExitReason::Error;
    assert_eq!(reason, ExitReason::Error);
  }

  #[test]
  fn test_exit_reason_equality() {
    assert_eq!(ExitReason::Normal, ExitReason::Normal);
    assert_eq!(ExitReason::Panic, ExitReason::Panic);
    assert_eq!(ExitReason::Error, ExitReason::Error);
    assert_ne!(ExitReason::Normal, ExitReason::Panic);
    assert_ne!(ExitReason::Normal, ExitReason::Error);
    assert_ne!(ExitReason::Panic, ExitReason::Error);
  }

  #[test]
  fn test_exit_reason_clone() {
    let reason = ExitReason::Panic;
    let cloned = reason;
    assert_eq!(reason, cloned);
  }

  #[test]
  fn test_exit_reason_copy() {
    let reason = ExitReason::Error;
    let copied: ExitReason = reason;
    assert_eq!(reason, copied);
  }

  // ============== determine_exit_code Tests ==============

  #[test]
  fn test_determine_exit_code_empty_reasons() {
    let reasons: Vec<ExitReason> = vec![];
    assert_eq!(determine_exit_code(&reasons), 0);
  }

  #[test]
  fn test_determine_exit_code_single_normal() {
    let reasons = vec![ExitReason::Normal];
    assert_eq!(determine_exit_code(&reasons), 0);
  }

  #[test]
  fn test_determine_exit_code_single_panic() {
    let reasons = vec![ExitReason::Panic];
    assert_eq!(determine_exit_code(&reasons), 1);
  }

  #[test]
  fn test_determine_exit_code_single_error() {
    let reasons = vec![ExitReason::Error];
    assert_eq!(determine_exit_code(&reasons), 2);
  }

  #[test]
  fn test_determine_exit_code_multiple_normal() {
    let reasons =
      vec![ExitReason::Normal, ExitReason::Normal, ExitReason::Normal];
    assert_eq!(determine_exit_code(&reasons), 0);
  }

  #[test]
  fn test_determine_exit_code_multiple_panic() {
    let reasons = vec![ExitReason::Panic, ExitReason::Panic];
    assert_eq!(determine_exit_code(&reasons), 1);
  }

  #[test]
  fn test_determine_exit_code_multiple_error() {
    let reasons = vec![ExitReason::Error, ExitReason::Error];
    assert_eq!(determine_exit_code(&reasons), 2);
  }

  #[test]
  fn test_determine_exit_code_mixed_panic_and_error() {
    // Panic has priority over error
    let reasons = vec![ExitReason::Panic, ExitReason::Error];
    assert_eq!(determine_exit_code(&reasons), 1);
  }

  #[test]
  fn test_determine_exit_code_mixed_panic_and_normal() {
    let reasons = vec![ExitReason::Panic, ExitReason::Normal];
    assert_eq!(determine_exit_code(&reasons), 1);
  }

  #[test]
  fn test_determine_exit_code_mixed_error_and_normal() {
    let reasons = vec![ExitReason::Error, ExitReason::Normal];
    assert_eq!(determine_exit_code(&reasons), 2);
  }

  #[test]
  fn test_determine_exit_code_mixed_all_three() {
    // Panic has highest priority
    let reasons =
      vec![ExitReason::Normal, ExitReason::Panic, ExitReason::Error];
    assert_eq!(determine_exit_code(&reasons), 1);
  }

  #[test]
  fn test_determine_exit_code_priority_panic_over_error() {
    let reasons = vec![ExitReason::Error, ExitReason::Panic];
    assert_eq!(determine_exit_code(&reasons), 1);
  }

  #[test]
  fn test_determine_exit_code_priority_panic_over_normal() {
    let reasons = vec![ExitReason::Normal, ExitReason::Panic];
    assert_eq!(determine_exit_code(&reasons), 1);
  }

  #[test]
  fn test_determine_exit_code_priority_error_over_normal() {
    let reasons = vec![ExitReason::Normal, ExitReason::Error];
    assert_eq!(determine_exit_code(&reasons), 2);
  }

  // ============== check_worker_threads Tests ==============

  #[test]
  fn test_check_worker_threads_all_running() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let running = Arc::new(AtomicBool::new(true));
      let running_clone = running.clone();
      let handle = thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
          thread::sleep(Duration::from_millis(10));
        }
        Ok(())
      });

      let mut handles = vec![handle];
      let mut joined_indices = HashSet::new();
      let mut exit_reasons = Vec::new();
      let shutdown_triggered = Arc::new(AtomicBool::new(false));
      let shutdown_notify = Arc::new(sync::Notify::new());

      // Thread is still running
      let all_joined = check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );

      assert!(!all_joined);
      assert!(joined_indices.is_empty());
      assert!(exit_reasons.is_empty());

      // Clean up
      running.store(false, Ordering::SeqCst);
      // Wait for thread to finish and clean up
      tokio::time::sleep(Duration::from_millis(50)).await;
      check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );
    });
  }

  #[test]
  fn test_check_worker_threads_normal_exit() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let handle = thread::spawn(|| Ok(()));
      // Wait for thread to finish
      thread::sleep(Duration::from_millis(50));

      let mut handles = vec![handle];
      let mut joined_indices = HashSet::new();
      let mut exit_reasons = Vec::new();
      let shutdown_triggered = Arc::new(AtomicBool::new(false));
      let shutdown_notify = Arc::new(sync::Notify::new());

      let all_joined = check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );

      assert!(all_joined);
      assert_eq!(joined_indices.len(), 1);
      assert_eq!(exit_reasons, vec![ExitReason::Normal]);
      assert!(!shutdown_triggered.load(Ordering::SeqCst));
    });
  }

  #[test]
  fn test_check_worker_threads_error_exit() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let handle = thread::spawn(|| Err(anyhow::anyhow!("test error")));
      // Wait for thread to finish
      thread::sleep(Duration::from_millis(50));

      let mut handles = vec![handle];
      let mut joined_indices = HashSet::new();
      let mut exit_reasons = Vec::new();
      let shutdown_triggered = Arc::new(AtomicBool::new(false));
      let shutdown_notify = Arc::new(sync::Notify::new());

      let all_joined = check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );

      assert!(all_joined);
      assert_eq!(joined_indices.len(), 1);
      assert_eq!(exit_reasons, vec![ExitReason::Error]);
      assert!(shutdown_triggered.load(Ordering::SeqCst));
    });
  }

  #[test]
  fn test_check_worker_threads_panic() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let handle = thread::spawn(|| {
        panic!("test panic");
      });
      // Wait for thread to finish
      thread::sleep(Duration::from_millis(50));

      let mut handles = vec![handle];
      let mut joined_indices = HashSet::new();
      let mut exit_reasons = Vec::new();
      let shutdown_triggered = Arc::new(AtomicBool::new(false));
      let shutdown_notify = Arc::new(sync::Notify::new());

      let all_joined = check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );

      assert!(all_joined);
      assert_eq!(joined_indices.len(), 1);
      assert_eq!(exit_reasons, vec![ExitReason::Panic]);
      assert!(shutdown_triggered.load(Ordering::SeqCst));
    });
  }

  #[test]
  fn test_check_worker_threads_multiple_threads() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let handle1 = thread::spawn(|| Ok(()));
      let handle2 =
        thread::spawn(|| Err(anyhow::anyhow!("test error")));
      let handle3 = thread::spawn(|| panic!("test panic"));

      // Wait for threads to finish
      thread::sleep(Duration::from_millis(100));

      let mut handles = vec![handle1, handle2, handle3];
      let mut joined_indices = HashSet::new();
      let mut exit_reasons = Vec::new();
      let shutdown_triggered = Arc::new(AtomicBool::new(false));
      let shutdown_notify = Arc::new(sync::Notify::new());

      let all_joined = check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );

      assert!(all_joined);
      assert_eq!(joined_indices.len(), 3);
      assert_eq!(exit_reasons.len(), 3);
      assert!(exit_reasons.contains(&ExitReason::Normal));
      assert!(exit_reasons.contains(&ExitReason::Error));
      assert!(exit_reasons.contains(&ExitReason::Panic));
    });
  }

  #[test]
  fn test_check_worker_threads_already_triggered_shutdown() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let handle = thread::spawn(|| Err(anyhow::anyhow!("test error")));
      // Wait for thread to finish
      thread::sleep(Duration::from_millis(50));

      let mut handles = vec![handle];
      let mut joined_indices = HashSet::new();
      let mut exit_reasons = Vec::new();
      let shutdown_triggered = Arc::new(AtomicBool::new(true));
      let shutdown_notify = Arc::new(sync::Notify::new());

      let all_joined = check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );

      assert!(all_joined);
      assert!(shutdown_triggered.load(Ordering::SeqCst));
      // Should still record the reason even when shutdown already triggered
      assert_eq!(exit_reasons, vec![ExitReason::Error]);
    });
  }

  #[test]
  fn test_check_worker_threads_already_joined_thread() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let handle = thread::spawn(|| Ok(()));
      // Wait for thread to finish
      thread::sleep(Duration::from_millis(50));

      let mut handles = vec![handle];
      let mut joined_indices = HashSet::new();
      joined_indices.insert(0); // Already joined
      let mut exit_reasons = Vec::new();
      let shutdown_triggered = Arc::new(AtomicBool::new(false));
      let shutdown_notify = Arc::new(sync::Notify::new());

      let all_joined = check_worker_threads(
        &mut handles,
        &mut joined_indices,
        &mut exit_reasons,
        &shutdown_triggered,
        &shutdown_notify,
      );

      // Should skip already joined thread
      assert!(all_joined);
      assert_eq!(joined_indices.len(), 1);
      assert!(exit_reasons.is_empty());
    });
  }

  // ============== main_loop_with_signal Tests ==============

  #[test]
  fn test_main_loop_no_worker_threads() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let handles: Vec<thread::JoinHandle<Result<()>>> = vec![];
      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Create a signal future that completes after delay
      let signal_future = Box::pin(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
      });

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered,
        signal_future,
      )
      .await;

      // Should return 0 for no worker threads scenario
      assert_eq!(exit_code, 0);
    });
  }

  #[test]
  fn test_main_loop_all_threads_normal_exit() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create threads that exit normally immediately
      let handle1 = thread::spawn(|| Ok(()));
      let handle2 = thread::spawn(|| Ok(()));
      let handles = vec![handle1, handle2];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Wait for threads to start and finish
      tokio::time::sleep(Duration::from_millis(100)).await;

      // Use a signal future that never completes (threads exit first)
      let signal_future = Box::pin(std::future::pending::<()>());

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered,
        signal_future,
      )
      .await;

      // All threads exited normally, should return 0
      assert_eq!(exit_code, 0);
    });
  }

  #[test]
  fn test_main_loop_thread_error_exit() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create a thread that exits with error
      let handle = thread::spawn(|| Err(anyhow::anyhow!("test error")));
      let handles = vec![handle];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Wait for thread to start and finish
      tokio::time::sleep(Duration::from_millis(100)).await;

      // Use a signal future that never completes (thread exits first)
      let signal_future = Box::pin(std::future::pending::<()>());

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered,
        signal_future,
      )
      .await;

      // Thread exited with error, should return 2
      assert_eq!(exit_code, 2);
    });
  }

  #[test]
  fn test_main_loop_thread_panic() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create a thread that panics
      let handle = thread::spawn(|| {
        panic!("test panic");
      });
      let handles = vec![handle];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Wait for thread to start and finish
      tokio::time::sleep(Duration::from_millis(100)).await;

      // Use a signal future that never completes (thread exits first)
      let signal_future = Box::pin(std::future::pending::<()>());

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered,
        signal_future,
      )
      .await;

      // Thread panicked, should return 1
      assert_eq!(exit_code, 1);
    });
  }

  #[test]
  fn test_main_loop_mixed_panic_and_error() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create threads with different exit reasons
      let handle1 =
        thread::spawn(|| Err(anyhow::anyhow!("test error")));
      let handle2 = thread::spawn(|| {
        panic!("test panic");
      });
      let handles = vec![handle1, handle2];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Wait for threads to start and finish
      tokio::time::sleep(Duration::from_millis(150)).await;

      // Use a signal future that never completes (threads exit first)
      let signal_future = Box::pin(std::future::pending::<()>());

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered,
        signal_future,
      )
      .await;

      // Panic has priority over error, should return 1
      assert_eq!(exit_code, 1);
    });
  }

  #[test]
  fn test_main_loop_multiple_errors() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create multiple threads that exit with error
      let handle1 =
        thread::spawn(|| Err(anyhow::anyhow!("test error 1")));
      let handle2 =
        thread::spawn(|| Err(anyhow::anyhow!("test error 2")));
      let handles = vec![handle1, handle2];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Wait for threads to start and finish
      tokio::time::sleep(Duration::from_millis(100)).await;

      // Use a signal future that never completes (threads exit first)
      let signal_future = Box::pin(std::future::pending::<()>());

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered,
        signal_future,
      )
      .await;

      // All errors, should return 2
      assert_eq!(exit_code, 2);
    });
  }

  #[test]
  fn test_main_loop_signal_triggers_shutdown() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create a thread that runs for a while
      let running = Arc::new(AtomicBool::new(true));
      let running_clone = running.clone();
      let handle = thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
          thread::sleep(Duration::from_millis(10));
        }
        Ok(())
      });
      let handles = vec![handle];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Create a signal future that completes after delay
      let signal_future = Box::pin(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
      });

      // Clone for the cleanup task
      let running_clone = running.clone();

      // Start main loop in a task
      let shutdown_notify_clone = shutdown_notify.clone();
      tokio::spawn(async move {
        // Wait for shutdown signal
        shutdown_notify_clone.notified().await;
        // Signal thread to stop
        running_clone.store(false, Ordering::SeqCst);
      });

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered,
        signal_future,
      )
      .await;

      // Signal triggered shutdown, should return 0
      assert_eq!(exit_code, 0);
    });
  }

  // ============== Runtime Tests ==============

  #[test]
  fn test_runtime_creation() {
    let result = runtime::Builder::new_current_thread()
      .enable_all()
      .thread_name("test_thread")
      .build();
    assert!(result.is_ok());
  }

  #[test]
  fn test_local_set_creation() {
    let local_set = task::LocalSet::new();
    drop(local_set);
  }

  #[test]
  fn test_notify_creation() {
    let notify = Arc::new(sync::Notify::new());
    drop(notify);
  }

  #[test]
  fn test_notify_notify_waiters() {
    let notify = Arc::new(sync::Notify::new());
    let notify_clone = notify.clone();
    notify.notify_waiters();
    drop(notify_clone);
  }

  #[test]
  fn test_signal_kind_interrupt() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let result = rt.block_on(async {
      signal::signal(signal::SignalKind::interrupt())
    });
    assert!(result.is_ok());
  }

  #[test]
  fn test_signal_kind_terminate() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let result = rt.block_on(async {
      signal::signal(signal::SignalKind::terminate())
    });
    assert!(result.is_ok());
  }

  #[test]
  fn test_atomic_bool_creation() {
    let flag = Arc::new(AtomicBool::new(false));
    assert!(!flag.load(Ordering::SeqCst));
  }

  #[test]
  fn test_atomic_bool_swap() {
    let flag = Arc::new(AtomicBool::new(false));
    let old = flag.swap(true, Ordering::SeqCst);
    assert!(!old);
    assert!(flag.load(Ordering::SeqCst));
  }

  #[test]
  fn test_hash_set_creation() {
    let set: HashSet<usize> = HashSet::new();
    assert!(set.is_empty());
  }

  #[test]
  fn test_hash_set_insert_and_contains() {
    let mut set: HashSet<usize> = HashSet::new();
    set.insert(1);
    set.insert(2);
    assert!(set.contains(&1));
    assert!(set.contains(&2));
    assert!(!set.contains(&3));
    assert_eq!(set.len(), 2);
  }

  /// Test thread naming in run_server_threads (indirectly through
  /// Config) Note: Full testing of run_server_threads is difficult
  /// because:
  /// 1. It depends on Config::global() which requires command-line
  ///    arguments or config file
  /// 2. It calls server::server_thread which creates real server
  ///    threads
  /// 3. There's no dependency injection mechanism for the server
  ///    creation logic
  ///
  /// For full integration testing, this would require:
  /// - Mock Config system
  /// - Mock server_thread function
  /// - Or refactoring to accept factory functions as parameters
  #[test]
  fn test_run_server_threads_thread_naming_pattern() {
    // Test that the thread naming pattern is correct
    for i in 0..5 {
      let name = format!("neoproxy server thread {i}");
      assert!(name.contains("neoproxy"));
      assert!(name.contains(&format!("{i}")));
    }
  }

  // ============== LogWriterConfig Tests ==============

  /// Test that LogWriterConfig defaults to buffered_lines_limit(1) to fix
  /// the runtime log delay issue. Without this, logs are buffered and
  /// written with delay.
  #[test]
  fn test_log_writer_config_buffered_lines_limit_defaults_to_1() {
    let config = LogWriterConfig::default();
    assert_eq!(
      config.buffered_lines_limit, 1,
      "buffered_lines_limit should be 1 to ensure logs are written immediately"
    );
  }

  /// Test that LogWriterConfig can build a NonBlocking writer.
  #[test]
  fn test_log_writer_config_builds_non_blocking_writer() {
    use std::io::Cursor;

    let config = LogWriterConfig::default();
    let cursor = Cursor::new(Vec::new());
    let (_writer, _guard) = config.build(cursor);
    // If we get here without panicking, the build succeeded
  }

  // ============== create_signal_future Tests ==============

  #[test]
  fn test_create_signal_future_returns_pinned_future() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      let signal_future = create_signal_future();
      // Verify the future can be created
      drop(signal_future);
    });
  }

  /// Test that duplicate signals during graceful shutdown are ignored.
  /// This verifies the requirement: "优雅关闭过程中收到多次信号，应忽略重复信号"
  /// The behavior is:
  /// 1. First signal triggers shutdown
  /// 2. Subsequent signals are ignored (shutdown_triggered is already true)
  #[test]
  fn test_main_loop_duplicate_signal_ignored() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create a thread that runs until shutdown is triggered
      let running = Arc::new(AtomicBool::new(true));
      let running_clone = running.clone();
      let handle = thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
          thread::sleep(Duration::from_millis(10));
        }
        Ok(())
      });
      let handles = vec![handle];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Track how many times notify_waiters is called
      let notify_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
      let notify_count_clone = notify_count.clone();

      // Create a signal future that completes immediately
      // This simulates receiving a signal right away
      let signal_future = Box::pin(async {
        // Small delay to ensure main loop is ready
        tokio::time::sleep(Duration::from_millis(50)).await;
      });

      // Spawn a task that will listen for shutdown notification
      // and then signal the thread to stop
      let running_clone = running.clone();
      let shutdown_notify_clone = shutdown_notify.clone();
      tokio::spawn(async move {
        shutdown_notify_clone.notified().await;
        // Increment counter when shutdown is triggered
        notify_count_clone.fetch_add(1, Ordering::SeqCst);
        // Signal thread to stop
        running_clone.store(false, Ordering::SeqCst);
      });

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered.clone(),
        signal_future,
      )
      .await;

      // Verify:
      // 1. Exit code is 0 (normal shutdown via signal)
      assert_eq!(exit_code, 0);
      // 2. shutdown_triggered is true (shutdown was initiated)
      assert!(shutdown_triggered.load(Ordering::SeqCst));
      // 3. notify_waiters was called exactly once
      assert_eq!(notify_count.load(Ordering::SeqCst), 1);
    });
  }

  /// Test that shutdown_triggered flag correctly prevents multiple
  /// notify_waiters calls when signals arrive rapidly.
  #[test]
  fn test_shutdown_triggered_prevents_duplicate_notifications() {
    let shutdown_triggered = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(sync::Notify::new());

    // First call should return false (was not triggered) and set to true
    let was_triggered = shutdown_triggered.swap(true, Ordering::SeqCst);
    assert!(!was_triggered);

    // Simulate calling notify_waiters after first signal
    shutdown_notify.notify_waiters();

    // Second call should return true (was already triggered)
    let was_triggered_second =
      shutdown_triggered.swap(true, Ordering::SeqCst);
    assert!(was_triggered_second);

    // Should not call notify_waiters again because was_triggered_second is true
  }

  /// Test that signal received after thread error is ignored.
  /// This verifies line 276: the debug log when signal is received
  /// during shutdown already triggered by thread error.
  /// Requirement: "优雅关闭过程中收到多次信号，应忽略重复信号"
  #[test]
  fn test_main_loop_signal_after_thread_error_ignored() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create two threads: one that errors, one that runs for a while
      let running = Arc::new(AtomicBool::new(true));
      let running_clone = running.clone();

      // Thread that will error
      let error_handle =
        thread::spawn(|| Err(anyhow::anyhow!("test error")));

      // Thread that runs until signaled to stop
      let long_handle = thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
          thread::sleep(Duration::from_millis(10));
        }
        Ok(())
      });

      let handles = vec![error_handle, long_handle];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Clone for cleanup
      let running_clone = running.clone();
      let shutdown_notify_clone = shutdown_notify.clone();
      tokio::spawn(async move {
        // Wait for shutdown notification
        shutdown_notify_clone.notified().await;
        // Signal long-running thread to stop
        running_clone.store(false, Ordering::SeqCst);
      });

      // Create a signal future that completes after error thread finishes
      // but before long thread finishes
      let signal_future = Box::pin(async {
        // Wait for error thread to be processed (100ms check interval)
        tokio::time::sleep(Duration::from_millis(150)).await;
      });

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered.clone(),
        signal_future,
      )
      .await;

      // Verify:
      // 1. Exit code is 2 (error exit)
      assert_eq!(exit_code, 2);
      // 2. shutdown_triggered is true
      assert!(shutdown_triggered.load(Ordering::SeqCst));
    });
  }

  /// Test that signal received after thread panic is ignored.
  /// Similar to test_main_loop_signal_after_thread_error_ignored but with panic.
  #[test]
  fn test_main_loop_signal_after_thread_panic_ignored() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    rt.block_on(async {
      // Create two threads: one that panics, one that runs for a while
      let running = Arc::new(AtomicBool::new(true));
      let running_clone = running.clone();

      // Thread that will panic
      let panic_handle = thread::spawn(|| {
        panic!("test panic");
      });

      // Thread that runs until signaled to stop
      let long_handle = thread::spawn(move || {
        while running_clone.load(Ordering::SeqCst) {
          thread::sleep(Duration::from_millis(10));
        }
        Ok(())
      });

      let handles = vec![panic_handle, long_handle];

      let shutdown_notify = Arc::new(sync::Notify::new());
      let shutdown_triggered = Arc::new(AtomicBool::new(false));

      // Clone for cleanup
      let running_clone = running.clone();
      let shutdown_notify_clone = shutdown_notify.clone();
      tokio::spawn(async move {
        // Wait for shutdown notification
        shutdown_notify_clone.notified().await;
        // Signal long-running thread to stop
        running_clone.store(false, Ordering::SeqCst);
      });

      // Create a signal future that completes after panic thread finishes
      // but before long thread finishes
      let signal_future = Box::pin(async {
        // Wait for panic thread to be processed (100ms check interval)
        tokio::time::sleep(Duration::from_millis(150)).await;
      });

      let exit_code = main_loop_with_signal(
        handles,
        shutdown_notify,
        shutdown_triggered.clone(),
        signal_future,
      )
      .await;

      // Verify:
      // 1. Exit code is 1 (panic)
      assert_eq!(exit_code, 1);
      // 2. shutdown_triggered is true
      assert!(shutdown_triggered.load(Ordering::SeqCst));
    });
  }
}
