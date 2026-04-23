use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync;
use tokio::task::JoinSet;

/// Shutdown Handle for `Listener`s.
pub struct ShutdownHandle {
  notify: Arc<sync::Notify>,
  is_shutdown: Arc<AtomicBool>,
}

impl ShutdownHandle {
  pub fn new() -> Self {
    Self {
      notify: Arc::new(sync::Notify::new()),
      is_shutdown: Arc::new(AtomicBool::new(false)),
    }
  }

  pub fn shutdown(&self) {
    self.is_shutdown.store(true, Ordering::SeqCst);
    self.notify.notify_waiters()
  }

  pub async fn notified(&self) {
    self.notify.notified().await
  }

  /// Check if shutdown has been triggered
  pub fn is_shutdown(&self) -> bool {
    self.is_shutdown.load(Ordering::SeqCst)
  }
}

impl Clone for ShutdownHandle {
  fn clone(&self) -> Self {
    Self {
      notify: self.notify.clone(),
      is_shutdown: self.is_shutdown.clone(),
    }
  }
}

/// Stream task tracker for graceful shutdown
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

  pub fn register(
    &self,
    stream_future: impl Future<Output = ()> + 'static,
  ) {
    self.streams.borrow_mut().spawn_local(stream_future);
  }

  pub fn register_connection(
    &self,
    conn_future: impl Future<Output = ()> + 'static,
  ) {
    self.connections.borrow_mut().spawn_local(conn_future);
  }

  pub fn shutdown(&self) {
    self.shutdown_handle.shutdown();
  }

  pub fn abort_all(&self) {
    self.streams.borrow_mut().abort_all();
    self.connections.borrow_mut().abort_all();
  }

  pub async fn wait_shutdown(&self) {
    while self.streams.borrow_mut().join_next().await.is_some() {}
    while self.connections.borrow_mut().join_next().await.is_some() {}
  }

  pub async fn wait_shutdown_with_timeout(
    &self,
    timeout: Duration,
  ) -> std::result::Result<(), ()> {
    tokio::time::timeout(timeout, self.wait_shutdown())
      .await
      .map_err(|_| ())
  }

  pub fn shutdown_handle(&self) -> ShutdownHandle {
    self.shutdown_handle.clone()
  }

  pub fn active_count(&self) -> usize {
    self.streams.borrow().len()
  }

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
  use std::time::Duration;

  #[test]
  fn test_shutdown_handle_new_is_not_shutdown() {
    let handle = ShutdownHandle::new();
    assert!(
      !handle.is_shutdown(),
      "New ShutdownHandle should not be in shutdown state"
    );
  }

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

  #[test]
  fn test_shutdown_handle_is_shutdown_after_shutdown() {
    let handle = ShutdownHandle::new();
    handle.shutdown();
    assert!(
      handle.is_shutdown(),
      "ShutdownHandle should be in shutdown state after shutdown() is called"
    );
  }

  #[test]
  fn test_shutdown_handle_clone_shares_state() {
    let handle = ShutdownHandle::new();
    let cloned = handle.clone();
    handle.shutdown();
    assert!(
      cloned.is_shutdown(),
      "Cloned ShutdownHandle should share shutdown state"
    );
  }

  #[test]
  fn test_shutdown_handle_multiple_shutdown_calls() {
    let handle = ShutdownHandle::new();
    handle.shutdown();
    handle.shutdown();
    handle.shutdown();
    assert!(
      handle.is_shutdown(),
      "Multiple shutdown calls should not cause issues"
    );
  }

  #[test]
  fn test_shutdown_handle_multiple_clones() {
    let handle = ShutdownHandle::new();
    let clone1 = handle.clone();
    let clone2 = clone1.clone();
    let clone3 = handle.clone();
    clone2.shutdown();
    assert!(handle.is_shutdown(), "Original should show shutdown");
    assert!(clone1.is_shutdown(), "Clone1 should show shutdown");
    assert!(clone2.is_shutdown(), "Clone2 should show shutdown");
    assert!(clone3.is_shutdown(), "Clone3 should show shutdown");
  }

  #[tokio::test]
  async fn test_shutdown_handle_notified_after_shutdown() {
    let handle = ShutdownHandle::new();
    let handle_clone = handle.clone();

    let notified = tokio::spawn(async move {
      handle_clone.notified().await;
      true
    });

    tokio::task::yield_now().await;
    handle.shutdown();

    let result =
      tokio::time::timeout(Duration::from_millis(100), notified).await;

    assert!(
      result.is_ok(),
      "notified() should complete after shutdown()"
    );
    assert!(
      result.unwrap().unwrap(),
      "notified() should have completed"
    );
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
