//! module: shutdown
//! responsibilities: persistent cancellation shared by tasks and worker
//! threads public operations: ShutdownHandle::{new, shutdown, notified,
//! is_shutdown}, SERVICE_SHUTDOWN_TIMEOUT data entities: ShutdownHandle
//! tests: shutdown_tests.rs

use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Second-phase grace shared by Service cleanup and retained protocol
/// drivers. They run concurrently; cancellation cleanup uses the
/// existing tracker abort budget.
pub(crate) const SERVICE_SHUTDOWN_TIMEOUT: Duration =
  Duration::from_secs(3);

#[derive(Clone, Default)]
pub(crate) struct ShutdownHandle {
  token: CancellationToken,
}

impl ShutdownHandle {
  pub(crate) fn new() -> Self {
    Self::default()
  }

  pub(crate) fn shutdown(&self) {
    self.token.cancel();
  }

  pub(crate) async fn notified(&self) {
    self.token.cancelled().await;
  }

  pub(crate) fn is_shutdown(&self) -> bool {
    self.token.is_cancelled()
  }
}
