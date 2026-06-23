//! Shutdown notification primitive.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync;

/// Shutdown Handle for listeners and services.
///
/// Provides a simple shutdown notification mechanism using a boolean
/// flag and async notification. Clones share the same underlying state.
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
