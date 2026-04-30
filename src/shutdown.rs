//! Shutdown notification primitive.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync;

/// Shutdown Handle for listeners and services.
///
/// Provides a simple shutdown notification mechanism using a boolean flag
/// and async notification. Clones share the same underlying state.
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

  /// Trigger shutdown notification.
  ///
  /// Sets the shutdown flag and notifies all waiters.
  pub fn shutdown(&self) {
    self.is_shutdown.store(true, Ordering::SeqCst);
    self.notify.notify_waiters()
  }

  /// Wait for shutdown notification.
  pub async fn notified(&self) {
    self.notify.notified().await
  }

  /// Check if shutdown has been triggered.
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

impl Default for ShutdownHandle {
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
}
