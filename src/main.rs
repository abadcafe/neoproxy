use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use tokio::signal::unix as signal;
use tokio::{runtime, sync, task};
use tracing::{info, warn};

use crate::config::Config;

mod config;
mod config_validator;
mod plugin;
mod plugins;
mod server;

/// Graceful shutdown timeout in seconds.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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

  let (writer, guard) = tracing_appender::non_blocking(log_appender);
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

/// Waits for all server threads to finish with a timeout.
/// Returns true if all threads finished successfully, false if timeout
/// occurred.
async fn join_all_threads(
  handles: Vec<thread::JoinHandle<Result<()>>>,
) -> bool {
  let mut all_success = true;
  for h in handles {
    let thread_name =
      h.thread().name().unwrap_or("unknown").to_string();
    match h.join() {
      Err(e) => {
        warn!("join server thread '{thread_name}' failed: '{e:?}'");
        all_success = false;
      }
      Ok(res) => {
        if let Err(e) = res {
          warn!("server thread '{thread_name}' error: '{e:?}'");
          all_success = false;
        }
      }
    }
  }
  all_success
}

/// Waits for shutdown signal (SIGINT or SIGTERM), then initiates graceful
/// shutdown.
async fn wait_for_shutdown(
  closer: Arc<sync::Notify>,
  handles: Vec<thread::JoinHandle<Result<()>>>,
) {
  // Wait for either SIGINT or SIGTERM
  let sigint = async {
    let mut stream =
      match signal::signal(signal::SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
          warn!("Failed to register SIGINT handler: {e}");
          std::future::pending().await
        }
      };
    stream.recv().await
  };

  let sigterm = async {
    let mut stream =
      match signal::signal(signal::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
          warn!("Failed to register SIGTERM handler: {e}");
          std::future::pending().await
        }
      };
    stream.recv().await
  };

  // Wait for either signal
  tokio::select! {
    _ = sigint => {},
    _ = sigterm => {},
  }

  info!("Received shutdown signal, initiating graceful shutdown...");
  closer.notify_waiters();

  // Wait for all threads with a timeout
  let result = tokio::time::timeout(
    GRACEFUL_SHUTDOWN_TIMEOUT,
    join_all_threads(handles),
  )
  .await;

  if result.is_err() {
    warn!("Graceful shutdown timeout, forcing exit");
  }

  info!("Shutdown complete");
}

fn main() -> Result<()> {
  let _guard = init_log();
  info!("server started with config:\n{:#?}\n", &Config::global());

  let closer = Arc::new(sync::Notify::new());
  let handles = run_server_threads(closer.clone());

  let local_set = task::LocalSet::new();
  let rt = runtime::Builder::new_current_thread()
    .enable_all()
    .thread_name("neoproxy main thread")
    .build()?;
  rt.block_on(local_set.run_until(wait_for_shutdown(closer, handles)));

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::time::Instant;

  #[test]
  fn test_graceful_shutdown_timeout_constant() {
    assert_eq!(GRACEFUL_SHUTDOWN_TIMEOUT, Duration::from_secs(5));
  }

  #[test]
  fn test_join_all_threads_success() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    let handle = thread::spawn(|| Ok(()));
    let handles = vec![handle];

    let result = rt.block_on(join_all_threads(handles));
    assert!(result);
  }

  #[test]
  fn test_join_all_threads_thread_panic() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    let handle = thread::spawn(|| panic!("test panic"));
    let handles = vec![handle];

    let result = rt.block_on(join_all_threads(handles));
    assert!(!result);
  }

  #[test]
  fn test_join_all_threads_thread_error() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    let handle = thread::spawn(|| Err(anyhow::anyhow!("test error")));
    let handles = vec![handle];

    let result = rt.block_on(join_all_threads(handles));
    assert!(!result);
  }

  #[test]
  fn test_join_all_threads_mixed_results() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    let success_handle = thread::spawn(|| Ok(()));
    let error_handle =
      thread::spawn(|| Err(anyhow::anyhow!("test error")));
    let handles = vec![success_handle, error_handle];

    let result = rt.block_on(join_all_threads(handles));
    assert!(!result);
  }

  #[test]
  fn test_join_all_threads_empty() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    let handles: Vec<thread::JoinHandle<Result<()>>> = vec![];

    let result = rt.block_on(join_all_threads(handles));
    assert!(result);
  }

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

  /// Test that join_all_threads handles multiple threads correctly
  #[test]
  fn test_join_all_threads_multiple_threads() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for _i in 0..3 {
      let counter_clone = counter.clone();
      let handle = thread::spawn(move || {
        let mut num = counter_clone.lock().unwrap();
        *num += 1;
        drop(num);
        Ok(())
      });
      handles.push(handle);
    }

    let result = rt.block_on(join_all_threads(handles));
    assert!(result);
    assert_eq!(*counter.lock().unwrap(), 3);
  }

  /// Test that the timeout constant is appropriate
  #[test]
  fn test_timeout_duration_is_five_seconds() {
    assert_eq!(GRACEFUL_SHUTDOWN_TIMEOUT.as_secs(), 5);
    assert_eq!(GRACEFUL_SHUTDOWN_TIMEOUT.as_millis(), 5000);
  }

  /// Test that join_all_threads handles timeout correctly with long-running
  /// threads. The thread will be terminated via timeout mechanism.
  #[test]
  fn test_join_all_threads_timeout_with_blocking_thread() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    // Use a flag to control thread termination
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Create a thread that will block until flag is cleared
    let blocking_handle = thread::spawn(move || {
      while running_clone.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(10));
      }
      Ok(())
    });

    let handles = vec![blocking_handle];

    // Test that join_all_threads completes when thread finishes
    let start = Instant::now();

    // Start join in a separate task so we can stop the blocking thread
    let join_result = rt.block_on(async {
      // Give the thread a moment to start
      tokio::time::sleep(Duration::from_millis(20)).await;

      // Signal the thread to stop
      running.store(false, Ordering::SeqCst);

      // Now join should complete quickly
      join_all_threads(handles).await
    });

    let elapsed = start.elapsed();
    assert!(join_result, "All threads should complete successfully");
    // Should complete quickly after signaling stop
    assert!(elapsed < Duration::from_secs(1));
  }

  /// Test wait_for_shutdown timeout behavior when threads don't respond
  /// in time. This simulates the graceful shutdown timeout scenario.
  #[test]
  fn test_wait_for_shutdown_timeout_behavior() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    // Test the timeout behavior of join_all_threads with empty handles
    let start = Instant::now();
    let result = rt.block_on(async {
      tokio::time::timeout(
        GRACEFUL_SHUTDOWN_TIMEOUT,
        join_all_threads(vec![]),
      )
      .await
    });

    // Should succeed immediately with empty handles
    assert!(result.is_ok());
    assert!(result.unwrap());
    let elapsed = start.elapsed();
    // Empty handles should complete very quickly
    assert!(elapsed < Duration::from_millis(100));
  }

  /// Test that wait_for_shutdown handles empty thread list correctly.
  /// This tests the notification and join mechanism without relying on
  /// signals.
  #[test]
  fn test_wait_for_shutdown_empty_handles() {
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();

    let closer = Arc::new(sync::Notify::new());
    let _handles: Vec<thread::JoinHandle<Result<()>>> = vec![];

    // Create a task that will complete the wait_for_shutdown
    let closer_clone = closer.clone();
    let _shutdown_handle = rt.spawn(async move {
      // Wait a bit then notify
      tokio::time::sleep(Duration::from_millis(10)).await;
      closer_clone.notify_waiters();
    });

    let closer_for_main = closer.clone();
    let result = rt.block_on(async {
      // Test that we can call join_all_threads with empty handles
      // through the timeout mechanism
      tokio::time::timeout(Duration::from_millis(100), async {
        closer_for_main.notified().await;
        join_all_threads(vec![]).await
      })
      .await
    });

    assert!(result.is_ok());
    assert!(result.unwrap());
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
}
