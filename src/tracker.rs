//! Task tracking for graceful shutdown.
//!
//! Provides [`StreamTracker`] for tracking async tasks with graceful
//! shutdown support. Supports dual-layer tracking (connections +
//! streams) for protocols like QUIC.

use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::time::Duration;

use tokio::task::{JoinError, JoinSet};

use crate::shutdown::ShutdownHandle;

/// Stream task tracker for graceful shutdown.
///
/// Tracks all active stream tasks and provides graceful shutdown
/// capabilities. Supports dual-layer tracking (connections + streams)
/// for protocols like QUIC that have both concepts.
///
/// For listeners that only need single-layer tracking (hyper, socks5),
/// use `register()` + `active_count()` only. The `connections` layer
/// remains empty with zero overhead.
pub(crate) struct StreamTracker {
  streams: Rc<RefCell<JoinSet<()>>>,
  connections: Rc<RefCell<JoinSet<()>>>,
  shutdown_handle: ShutdownHandle,
}

impl StreamTracker {
  pub(crate) fn new() -> Self {
    Self {
      streams: Rc::new(RefCell::new(JoinSet::new())),
      connections: Rc::new(RefCell::new(JoinSet::new())),
      shutdown_handle: ShutdownHandle::new(),
    }
  }

  /// Register a stream task.
  pub(crate) fn register(
    &self,
    stream_future: impl Future<Output = ()> + 'static,
  ) {
    self.streams.borrow_mut().spawn_local(stream_future);
  }

  /// Register a connection task (for protocols like QUIC).
  /// Returns an AbortHandle for checking if the task is still running.
  pub(crate) fn register_connection(
    &self,
    conn_future: impl Future<Output = ()> + 'static,
  ) -> tokio::task::AbortHandle {
    self.connections.borrow_mut().spawn_local(conn_future)
  }

  /// Trigger shutdown notification.
  pub(crate) fn shutdown(&self) {
    self.shutdown_handle.shutdown();
  }

  /// Abort all tracked tasks immediately.
  pub(crate) fn abort_all(&self) {
    self.streams.borrow_mut().abort_all();
    self.connections.borrow_mut().abort_all();
  }

  /// Drain aborted tasks from the JoinSet with a safety timeout.
  ///
  /// After `abort_all()`, tasks are marked cancelled but remain in the
  /// JoinSet until polled via `join_next()`. This method drains them
  /// so `active_count()` reflects the true state.
  ///
  /// A timeout is applied because aborted tasks may still be holding
  /// locks or in CPU-bound loops, preventing immediate cancellation.
  pub(crate) async fn drain(&self) {
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
      drain_join_set(&self.streams).await;
      drain_join_set(&self.connections).await;
    })
    .await;
  }

  /// Wait for all tasks to complete.
  pub(crate) async fn wait_shutdown(&self) {
    drain_join_set(&self.streams).await;
    drain_join_set(&self.connections).await;
  }

  /// Perform a graceful shutdown with timeout.
  ///
  /// Triggers shutdown, then waits for all active tasks to complete
  /// within the given timeout. If the timeout expires, forcefully
  /// aborts remaining tasks.
  pub(crate) async fn graceful_shutdown(&self, timeout: Duration) {
    self.shutdown();
    let result =
      tokio::time::timeout(timeout, self.wait_shutdown()).await;
    if result.is_err() {
      tracing::warn!(
        "graceful shutdown timeout ({:?}) expired, aborting {} \
         remaining connections",
        timeout,
        self.active_count()
      );
      self.abort_all();
    }
  }

  /// Wait with timeout.
  pub(crate) async fn wait_shutdown_with_timeout(
    &self,
    timeout: Duration,
  ) -> std::result::Result<(), ()> {
    tokio::time::timeout(timeout, self.wait_shutdown())
      .await
      .map_err(|_| ())
  }

  /// Get shutdown handle for listening in tasks.
  pub(crate) fn shutdown_handle(&self) -> ShutdownHandle {
    self.shutdown_handle.clone()
  }

  /// Count of active stream tasks.
  pub(crate) fn active_count(&self) -> usize {
    self.streams.borrow().len()
  }
}

impl Default for StreamTracker {
  fn default() -> Self {
    Self::new()
  }
}

async fn join_next(
  join_set: &RefCell<JoinSet<()>>,
) -> Option<Result<(), JoinError>> {
  poll_fn(|cx| join_set.borrow_mut().poll_join_next(cx)).await
}

async fn drain_join_set(join_set: &RefCell<JoinSet<()>>) {
  while join_next(join_set).await.is_some() {}
}
