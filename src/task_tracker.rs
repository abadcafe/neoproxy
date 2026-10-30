//! module: task_tracker
//! responsibility: own worker-local tasks through shutdown
//! public operations:
//! TaskTracker::{new,register,monitor,shutdown,abort_all,
//! drain,wait_shutdown,graceful_shutdown,wait_shutdown_with_timeout,
//! shutdown_handle,active_count}, ABORT_DRAIN_TIMEOUT
//! data entities: TaskTracker
//! tests: task_tracker_tests.rs
pub(crate) mod background;
mod lifecycle;
use std::cell::RefCell;
use std::future::Future;
use std::time::Duration;

pub(crate) use lifecycle::ABORT_DRAIN_TIMEOUT;
use lifecycle::{Lifecycle, TaskSet};
use tokio::task::JoinSet;

use crate::shutdown::ShutdownHandle;

pub(crate) struct TaskTracker {
  tasks: RefCell<JoinSet<()>>,
  lifecycle: Lifecycle,
}
impl TaskSet for TaskTracker {
  fn with<T>(&self, action: impl FnOnce(&mut JoinSet<()>) -> T) -> T {
    action(&mut self.tasks.borrow_mut())
  }
}
impl TaskTracker {
  pub(crate) fn new() -> Self {
    Self {
      tasks: RefCell::new(JoinSet::new()),
      lifecycle: Lifecycle::new(),
    }
  }

  pub(crate) fn register(
    &self,
    future: impl Future<Output = ()> + 'static,
  ) -> tokio::task::AbortHandle {
    self.lifecycle.register(self, |tasks| tasks.spawn_local(future))
  }

  pub(crate) fn monitor(&self) -> impl Future<Output = ()> + '_ {
    self.lifecycle.monitor(self)
  }

  pub(crate) fn shutdown(&self) {
    self.lifecycle.shutdown();
  }

  pub(crate) fn abort_all(&self) {
    self.lifecycle.abort_all(self);
  }

  pub(crate) async fn drain(&self) {
    self.lifecycle.drain(self).await;
  }

  pub(crate) async fn wait_shutdown(&self) {
    self.lifecycle.wait_shutdown(self).await;
  }

  pub(crate) async fn graceful_shutdown(&self, timeout: Duration) {
    self.lifecycle.graceful_shutdown(self, timeout).await;
  }

  pub(crate) async fn wait_shutdown_with_timeout(
    &self,
    timeout: Duration,
  ) -> Result<(), ()> {
    self.lifecycle.wait_shutdown_with_timeout(self, timeout).await
  }

  pub(crate) fn shutdown_handle(&self) -> ShutdownHandle {
    self.lifecycle.shutdown_handle()
  }

  pub(crate) fn active_count(&self) -> usize {
    self.lifecycle.active_count(self)
  }
}
impl Default for TaskTracker {
  fn default() -> Self {
    Self::new()
  }
}
