//! Task tracking for graceful shutdown.
//!
//! Provides [`StreamTracker`] for tracking async tasks with graceful shutdown support.
//! Supports dual-layer tracking (connections + streams) for protocols like QUIC.

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use tokio::task::JoinSet;

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
pub struct StreamTracker {
  streams: Rc<RefCell<JoinSet<()>>>,
  connections: Rc<RefCell<JoinSet<()>>>,
  shutdown_handle: ShutdownHandle,
}

impl StreamTracker {
  pub fn new() -> Self {
    Self {
      streams: Rc::new(RefCell::new(JoinSet::new())),
      connections: Rc::new(RefCell::new(JoinSet::new())),
      shutdown_handle: ShutdownHandle::new(),
    }
  }

  /// Register a stream task.
  pub fn register(
    &self,
    stream_future: impl Future<Output = ()> + 'static,
  ) {
    self.streams.borrow_mut().spawn_local(stream_future);
  }

  /// Register a connection task (for protocols like QUIC).
  pub fn register_connection(
    &self,
    conn_future: impl Future<Output = ()> + 'static,
  ) {
    self.connections.borrow_mut().spawn_local(conn_future);
  }

  /// Trigger shutdown notification.
  pub fn shutdown(&self) {
    self.shutdown_handle.shutdown();
  }

  /// Abort all tracked tasks immediately.
  pub fn abort_all(&self) {
    self.streams.borrow_mut().abort_all();
    self.connections.borrow_mut().abort_all();
  }

  /// Wait for all tasks to complete.
  pub async fn wait_shutdown(&self) {
    while self.streams.borrow_mut().join_next().await.is_some() {}
    while self.connections.borrow_mut().join_next().await.is_some() {}
  }

  /// Wait with timeout.
  pub async fn wait_shutdown_with_timeout(
    &self,
    timeout: Duration,
  ) -> std::result::Result<(), ()> {
    tokio::time::timeout(timeout, self.wait_shutdown())
      .await
      .map_err(|_| ())
  }

  /// Get shutdown handle for listening in tasks.
  pub fn shutdown_handle(&self) -> ShutdownHandle {
    self.shutdown_handle.clone()
  }

  /// Count of active stream tasks.
  pub fn active_count(&self) -> usize {
    self.streams.borrow().len()
  }

  /// Count of active connection tasks.
  pub fn connection_count(&self) -> usize {
    self.connections.borrow().len()
  }
}

impl Default for StreamTracker {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_stream_tracker_new() {
    let tracker = StreamTracker::new();
    assert_eq!(tracker.active_count(), 0);
    assert_eq!(tracker.connection_count(), 0);
  }

  #[test]
  fn test_stream_tracker_default() {
    let tracker = StreamTracker::default();
    assert_eq!(tracker.active_count(), 0);
  }

  #[tokio::test]
  async fn test_stream_tracker_register() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_register_multiple() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {});
        tracker.register(async {});
        tracker.register(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 3);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_shutdown() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        let shutdown_handle = tracker.shutdown_handle();

        let notified = Rc::new(std::cell::Cell::new(false));
        let notified_clone = notified.clone();
        tracker.register(async move {
          shutdown_handle.notified().await;
          notified_clone.set(true);
        });
        tokio::task::yield_now().await;

        tracker.shutdown();
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
        assert!(notified.get());
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_abort_all() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register(async {
          std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 1);

        tracker.abort_all();
        tracker.wait_shutdown().await;
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }

  #[test]
  fn test_stream_tracker_abort_all_empty() {
    let tracker = StreamTracker::new();
    tracker.abort_all();
    assert_eq!(tracker.active_count(), 0);
  }

  #[test]
  fn test_stream_tracker_shutdown_handle() {
    let tracker = StreamTracker::new();
    let _handle = tracker.shutdown_handle();
  }

  #[tokio::test]
  async fn test_stream_tracker_connection_count() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let tracker = StreamTracker::new();
        tracker.register_connection(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.connection_count(), 1);
        assert_eq!(tracker.active_count(), 0);
      })
      .await;
  }
}
