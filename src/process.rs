//! module: process
//! responsibilities: supervise worker threads and propagate process
//! shutdown public operations: run, shutdown_signal
//! data entities: ExitReason
//! tests: process_tests.rs
use std::future::Future;
use std::pin::Pin;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use tokio::signal::unix as signal;
use tracing::{error, info, warn};

use crate::shutdown::ShutdownHandle;
const THREAD_CHECK_INTERVAL: Duration = Duration::from_millis(100);

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

/// Create a signal waiting future for SIGINT/SIGTERM.
pub(crate) fn shutdown_signal()
-> Pin<Box<dyn Future<Output = ()> + Send>> {
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

/// Supervise scoped workers and join every handle before returning.
/// Joining records worker panics as process failure, so the enclosing
/// scope has no unjoined panic to propagate a second time.
pub(crate) async fn run(
  handles: Vec<thread::ScopedJoinHandle<'_, Result<()>>>,
  shutdown: ShutdownHandle,
  signal_future: impl Future<Output = ()>,
) -> i32 {
  tokio::pin!(signal_future);
  let mut handles: Vec<_> = handles.into_iter().map(Some).collect();
  let mut exit_reasons = Vec::new();
  if handles.is_empty() {
    signal_future.await;
    shutdown.shutdown();
    return 0;
  }
  while handles.iter().any(Option::is_some) {
    tokio::select! {
      _ = signal_future.as_mut(), if !shutdown.is_shutdown() => {
        info!("received shutdown signal");
        shutdown.shutdown();
      }
      _ = tokio::time::sleep(THREAD_CHECK_INTERVAL) => {
        for slot in &mut handles {
          if slot.as_ref().is_some_and(thread::ScopedJoinHandle::is_finished) {
            let handle = slot.take().expect("finished worker exists");
            let reason = match handle.join() {
              Err(payload) => { error!("server thread panicked: {payload:?}"); ExitReason::Panic }
              Ok(Err(error)) => { error!("server thread failed: {error}"); ExitReason::Error }
              Ok(Ok(())) => ExitReason::Normal,
            };
            exit_reasons.push(reason);
            // Every worker exit must stop its peers, including an
            // unexpected normal return.
            shutdown.shutdown();
          }
        }
      }
    }
  }
  info!("shutdown complete");
  determine_exit_code(&exit_reasons)
}
