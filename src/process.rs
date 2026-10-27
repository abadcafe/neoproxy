//! module: process
//! responsibilities: supervise worker threads and propagate process
//! shutdown public operations: Workers::{new, spawn, run},
//! shutdown_signal data entities: Workers, Completion, ExitReason
//! tests: process_tests.rs
use std::future::Future;
use std::pin::Pin;
use std::thread;

use anyhow::Result;
use tokio::signal::unix as signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::shutdown::ShutdownHandle;

/// Creating workers through their supervisor makes completion
/// notification mandatory, including normal errors and unwinding.
pub(crate) struct Workers<'scope> {
  handles: Vec<Option<thread::ScopedJoinHandle<'scope, Result<()>>>>,
  completed: mpsc::UnboundedReceiver<usize>,
  notify: mpsc::UnboundedSender<usize>,
  shutdown: ShutdownHandle,
}

struct Completion {
  index: usize,
  notify: mpsc::UnboundedSender<usize>,
}

impl Drop for Completion {
  fn drop(&mut self) {
    let _ = self.notify.send(self.index);
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

impl<'scope> Workers<'scope> {
  pub(crate) fn new(shutdown: ShutdownHandle) -> Self {
    let (notify, completed) = mpsc::unbounded_channel();
    Self { handles: Vec::new(), completed, notify, shutdown }
  }

  pub(crate) fn spawn<'env, F>(
    &mut self,
    scope: &'scope thread::Scope<'scope, 'env>,
    name: &str,
    task: F,
  ) -> std::io::Result<()>
  where
    F: FnOnce() -> Result<()> + Send + 'scope,
  {
    let index = self.handles.len();
    let notify = self.notify.clone();
    let handle = thread::Builder::new()
      .name(name.to_owned())
      .spawn_scoped(scope, move || {
        // Created inside the thread: a failed spawn cannot enqueue an
        // event for a handle which was never registered. This guard is
        // dropped after the worker body and its local resources.
        let _completion = Completion { index, notify };
        task()
      })?;
    self.handles.push(Some(handle));
    Ok(())
  }

  /// Join every notified worker before returning. Joining records
  /// worker panics, so the enclosing scope cannot propagate them again.
  pub(crate) async fn run(
    mut self,
    signal_future: impl Future<Output = ()>,
  ) -> i32 {
    tokio::pin!(signal_future);
    let mut exit_reasons = Vec::new();
    if self.handles.is_empty() {
      signal_future.await;
      self.shutdown.shutdown();
      return 0;
    }
    let mut remaining = self.handles.len();
    while remaining != 0 {
      tokio::select! {
        _ = signal_future.as_mut(), if !self.shutdown.is_shutdown() => {
          info!("received shutdown signal");
          self.shutdown.shutdown();
        }
        completed = self.completed.recv() => {
          let index = completed
            .expect("registered workers retain completion senders");
          let handle = self.handles[index]
            .take()
            .expect("worker completes exactly once");
          let reason = match handle.join() {
            Err(payload) => {
              error!("server thread panicked: {payload:?}");
              ExitReason::Panic
            }
            Ok(Err(error)) => {
              error!("server thread failed: {error}");
              ExitReason::Error
            }
            Ok(Ok(())) => ExitReason::Normal,
          };
          exit_reasons.push(reason);
          // Every worker exit must stop its peers, including an
          // unexpected normal return.
          self.shutdown.shutdown();
          remaining -= 1;
        }
      }
    }
    info!("shutdown complete");
    determine_exit_code(&exit_reasons)
  }
}

impl Drop for Workers<'_> {
  fn drop(&mut self) {
    if self.handles.iter().any(Option::is_some) {
      self.shutdown.shutdown();
      for handle in self.handles.iter_mut().filter_map(Option::take) {
        let _ = handle.join();
      }
    }
  }
}
