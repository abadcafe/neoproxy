//! Shared TCP listener base for lifecycle management.
//!
//! Provides [`TcpListenerBase`] which encapsulates the common lifecycle
//! pattern shared by HTTP and HTTPS listeners: JoinSet management,
//! stream tracking, and graceful shutdown.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use anyhow::Result;
use tokio::task;

use crate::tracker::StreamTracker;

use super::LISTENER_SHUTDOWN_TIMEOUT;

/// Shared base for TCP-based listeners.
///
/// Manages the listener JoinSet, stream tracker, and graceful shutdown
/// lifecycle. Protocol-specific listeners (HTTP, HTTPS) delegate
/// lifecycle management to this base while keeping their own accept
/// loop logic.
pub(crate) struct TcpListenerBase {
  pub(crate) listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  pub(crate) stream_tracker: Rc<StreamTracker>,
  pub(crate) graceful_shutdown_timeout: Duration,
}

impl TcpListenerBase {
  /// Create a new TcpListenerBase with default configuration.
  pub(crate) fn new() -> Self {
    Self {
      listening_set: Rc::new(RefCell::new(task::JoinSet::new())),
      stream_tracker: Rc::new(StreamTracker::new()),
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
    }
  }

  /// Spawn tasks and return a future that manages their lifecycle.
  ///
  /// Spawns each task into the listening set, then waits for shutdown
  /// notification. After shutdown, joins all tasks and performs
  /// graceful shutdown of the stream tracker.
  pub(crate) fn start_with_tasks<I>(
    &self,
    tasks: I,
  ) -> Pin<Box<dyn Future<Output = Result<()>>>>
  where
    I: IntoIterator<Item = Pin<Box<dyn Future<Output = Result<()>>>>>,
  {
    let listening_set = self.listening_set.clone();
    for task in tasks {
      listening_set.borrow_mut().spawn_local(task);
    }
    let stream_tracker = self.stream_tracker.clone();
    let shutdown = self.stream_tracker.shutdown_handle();
    let graceful_timeout = self.graceful_shutdown_timeout;
    Box::pin(async move {
      shutdown.notified().await;
      while let Some(res) = listening_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => {
            tracing::error!("listening join error: {}", e)
          }
          Ok(res) => {
            if let Err(e) = res {
              tracing::error!("listening error: {}", e)
            }
          }
        }
      }
      stream_tracker.graceful_shutdown(graceful_timeout).await;
      Ok(())
    })
  }

  /// Trigger graceful shutdown.
  pub(crate) fn stop(&self) {
    self.stream_tracker.shutdown()
  }

  /// Get a shutdown handle for use in accept loops.
  pub(crate) fn shutdown_handle(
    &self,
  ) -> crate::shutdown::ShutdownHandle {
    self.stream_tracker.shutdown_handle()
  }

  /// Get a clone of the stream tracker.
  pub(crate) fn stream_tracker(&self) -> Rc<StreamTracker> {
    self.stream_tracker.clone()
  }
}
