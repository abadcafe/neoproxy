//! module: task_tracker
//! responsibility: own asynchronous task lifetimes through
//! shutdown
//! public operations: ABORT_DRAIN_TIMEOUT, TaskTracker, new,
//! register, register_on, shutdown, abort_all, drain,
//! wait_shutdown, graceful_shutdown, wait_shutdown_with_timeout,
//! shutdown_handle, active_count
//! data entities: TaskTracker
//! tests: task_tracker_tests.rs, task_tracker_background_tests.rs

use std::future::{Future, poll_fn};
use std::sync::Mutex;
use std::time::Duration;

use tokio::task::{JoinError, JoinSet};

use crate::shutdown::ShutdownHandle;

pub(crate) const ABORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// One group of tasks sharing a cooperative shutdown
/// notification. Owners define shutdown ordering between groups. Tasks
/// must explicitly observe the notification and complete their
/// asynchronous cleanup.
pub(crate) struct TaskTracker {
  tasks: Mutex<JoinSet<()>>,
  shutdown_handle: ShutdownHandle,
}

impl TaskTracker {
  pub(crate) fn new() -> Self {
    Self {
      tasks: Mutex::new(JoinSet::new()),
      shutdown_handle: ShutdownHandle::new(),
    }
  }

  /// Spawn and track a local task.
  pub(crate) fn register(
    &self,
    task_future: impl Future<Output = ()> + 'static,
  ) -> tokio::task::AbortHandle {
    reap_completed(&self.tasks);
    self
      .tasks
      .lock()
      .expect("task tracker poisoned")
      .spawn_local(task_future)
  }

  /// Spawn a Send task on the runtime owned by a shared resource.
  /// This uses the same lifecycle semantics as local registration.
  pub(crate) fn register_on(
    &self,
    runtime: &tokio::runtime::Handle,
    task: impl Future<Output = ()> + Send + 'static,
  ) {
    reap_completed(&self.tasks);
    self
      .tasks
      .lock()
      .expect("task tracker poisoned")
      .spawn_on(task, runtime);
  }

  /// Trigger shutdown notification.
  pub(crate) fn shutdown(&self) {
    self.shutdown_handle.shutdown();
  }

  /// Abort all tracked tasks immediately.
  pub(crate) fn abort_all(&self) {
    self.tasks.lock().expect("task tracker poisoned").abort_all();
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
    let _ = tokio::time::timeout(ABORT_DRAIN_TIMEOUT, async {
      drain_join_set(&self.tasks).await;
    })
    .await;
  }

  /// Wait for all tasks to complete.
  pub(crate) async fn wait_shutdown(&self) {
    drain_join_set(&self.tasks).await;
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
         remaining tasks",
        timeout,
        self.active_count()
      );
      self.abort_all();
      self.drain().await;
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

  /// Count all unfinished tasks after collecting completed results.
  pub(crate) fn active_count(&self) -> usize {
    reap_completed(&self.tasks);
    self.tasks.lock().expect("task tracker poisoned").len()
  }
}

impl Default for TaskTracker {
  fn default() -> Self {
    Self::new()
  }
}

async fn join_next(
  join_set: &Mutex<JoinSet<()>>,
) -> Option<Result<(), JoinError>> {
  poll_fn(|cx| {
    join_set.lock().expect("task tracker poisoned").poll_join_next(cx)
  })
  .await
}

async fn drain_join_set(join_set: &Mutex<JoinSet<()>>) {
  while let Some(result) = join_next(join_set).await {
    propagate_task_panic(result);
  }
}

fn reap_completed(join_set: &Mutex<JoinSet<()>>) {
  while let Some(result) =
    join_set.lock().expect("task tracker poisoned").try_join_next()
  {
    propagate_task_panic(result);
  }
}

// Tokio turns spawned-task panics into JoinError values. A panic is a
// programming error, not a recoverable connection failure: deliberately
// resume the original unwind so listener/worker supervision observes
// it. Expected cancellation from abort_all() is not a programming
// error.
fn propagate_task_panic(result: Result<(), JoinError>) {
  if let Err(error) = result
    && error.is_panic()
  {
    tracing::error!(
      task_id = %error.id(),
      error = %error,
      "tracked task panicked; propagating programming failure"
    );
    std::panic::resume_unwind(error.into_panic());
  }
}
