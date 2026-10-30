//! module: background
//! responsibility: own cross-thread transport tasks through shutdown
//! public operations:
//! TaskTracker::{new,register_on,monitor,shutdown,wait_shutdown,
//! graceful_shutdown,shutdown_handle}
//! data entities: TaskTracker
//! tests: task_tracker_background_tests.rs
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use tokio::task::JoinSet;

use super::lifecycle::{Lifecycle, TaskSet};
use crate::shutdown::ShutdownHandle;
pub(crate) struct TaskTracker {
  tasks: Mutex<JoinSet<()>>,
  lifecycle: Lifecycle,
}
impl TaskSet for TaskTracker {
  fn with<T>(&self, action: impl FnOnce(&mut JoinSet<()>) -> T) -> T {
    action(&mut self.tasks.lock().expect("background tasks poisoned"))
  }
}
impl TaskTracker {
  pub(crate) fn new() -> Self {
    Self {
      tasks: Mutex::new(JoinSet::new()),
      lifecycle: Lifecycle::new(),
    }
  }

  pub(crate) fn register_on(
    &self,
    runtime: &tokio::runtime::Handle,
    future: impl Future<Output = ()> + Send + 'static,
  ) {
    self
      .lifecycle
      .register(self, |tasks| tasks.spawn_on(future, runtime));
  }

  pub(crate) fn monitor(&self) -> impl Future<Output = ()> + '_ {
    self.lifecycle.monitor(self)
  }

  pub(crate) fn shutdown(&self) {
    self.lifecycle.shutdown();
  }

  #[cfg(test)]
  pub(crate) async fn wait_shutdown(&self) {
    self.lifecycle.wait_shutdown(self).await;
  }

  pub(crate) async fn graceful_shutdown(&self, timeout: Duration) {
    self.lifecycle.graceful_shutdown(self, timeout).await;
  }

  pub(crate) fn shutdown_handle(&self) -> ShutdownHandle {
    self.lifecycle.shutdown_handle()
  }
}
impl Default for TaskTracker {
  fn default() -> Self {
    Self::new()
  }
}
