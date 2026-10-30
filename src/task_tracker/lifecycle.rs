//! module: lifecycle
//! responsibility: supervise task completion and cooperative shutdown
//! public operations: Lifecycle, TaskSet,
//! ABORT_DRAIN_TIMEOUT data entities: Lifecycle, TaskSet
//! tests: task_tracker_tests.rs, task_tracker_background_tests.rs
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use futures_util::task::AtomicWaker;
use tokio::task::{JoinError, JoinSet};

use crate::shutdown::ShutdownHandle;

pub(crate) const ABORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) trait TaskSet {
  fn with<T>(&self, action: impl FnOnce(&mut JoinSet<()>) -> T) -> T;
}

/// One group of tasks sharing a cooperative shutdown
/// notification. Owners define shutdown ordering between groups. Tasks
/// must explicitly observe the notification and complete their
/// asynchronous cleanup.
pub(super) struct Lifecycle {
  shutdown_handle: ShutdownHandle,
  monitor_waker: AtomicWaker,
}

impl Lifecycle {
  pub(super) fn new() -> Self {
    Self {
      shutdown_handle: ShutdownHandle::new(),
      monitor_waker: AtomicWaker::new(),
    }
  }

  pub(super) fn register<T>(
    &self,
    tasks: &impl TaskSet,
    spawn: impl FnOnce(&mut JoinSet<()>) -> T,
  ) -> T {
    reap_completed(tasks);
    let result = tasks.with(spawn);
    self.monitor_waker.wake();
    result
  }

  /// Continuously collect task outcomes, including when admission is
  /// idle. Exactly one lifecycle owner polls this monitor; drop it
  /// before entering the shutdown drain. Empty groups remain pending.
  /// Registration wakes this monitor, and JoinSet wakes it on task
  /// completion. No timer or separate notification loop is needed.
  pub(super) fn monitor<'a>(
    &'a self,
    tasks: &'a impl TaskSet,
  ) -> impl Future<Output = ()> + 'a {
    poll_fn(|cx| {
      // Register before inspecting the set: a concurrent registration
      // must either be visible to poll_join_next or wake this waiter.
      // JoinSet itself does not register a waiter when it is empty.
      self.monitor_waker.register(cx.waker());
      loop {
        let result = tasks.with(|tasks| tasks.poll_join_next(cx));
        match result {
          // The set lock is released before propagating a panic so the
          // owner can still drop/clean up the tracker during unwinding.
          Poll::Ready(Some(result)) => propagate_task_panic(result),
          Poll::Ready(None) | Poll::Pending => return Poll::Pending,
        }
      }
    })
  }

  /// Trigger shutdown notification.
  pub(super) fn shutdown(&self) {
    self.shutdown_handle.shutdown();
  }

  /// Abort all tracked tasks immediately.
  pub(super) fn abort_all(&self, tasks: &impl TaskSet) {
    tasks.with(|tasks| tasks.abort_all());
  }

  /// Drain aborted tasks from the JoinSet with a safety timeout.
  ///
  /// After `abort_all()`, tasks are marked cancelled but remain in the
  /// JoinSet until polled via `join_next()`. This method drains them
  /// so `active_count()` reflects the true state.
  ///
  /// A timeout is applied because aborted tasks may still be holding
  /// locks or in CPU-bound loops, preventing immediate cancellation.
  pub(super) async fn drain(&self, tasks: &impl TaskSet) {
    let _ = tokio::time::timeout(ABORT_DRAIN_TIMEOUT, async {
      drain_join_set(tasks).await;
    })
    .await;
  }

  /// Wait for all tasks to complete.
  pub(super) async fn wait_shutdown(&self, tasks: &impl TaskSet) {
    drain_join_set(tasks).await;
  }

  /// Perform a graceful shutdown with timeout.
  ///
  /// Triggers shutdown, then waits for all active tasks to complete
  /// within the given timeout. If the timeout expires, forcefully
  /// aborts remaining tasks.
  pub(super) async fn graceful_shutdown(
    &self,
    tasks: &impl TaskSet,
    timeout: Duration,
  ) {
    self.shutdown();
    let result =
      tokio::time::timeout(timeout, self.wait_shutdown(tasks)).await;
    if result.is_err() {
      tracing::warn!(
        "graceful shutdown timeout ({:?}) expired, aborting {} \
         remaining tasks",
        timeout,
        self.active_count(tasks)
      );
      self.abort_all(tasks);
      self.drain(tasks).await;
    }
  }

  /// Wait with timeout.
  pub(super) async fn wait_shutdown_with_timeout(
    &self,
    tasks: &impl TaskSet,
    timeout: Duration,
  ) -> std::result::Result<(), ()> {
    tokio::time::timeout(timeout, self.wait_shutdown(tasks))
      .await
      .map_err(|_| ())
  }

  /// Get shutdown handle for listening in tasks.
  pub(super) fn shutdown_handle(&self) -> ShutdownHandle {
    self.shutdown_handle.clone()
  }

  /// Count all unfinished tasks after collecting completed results.
  pub(super) fn active_count(&self, tasks: &impl TaskSet) -> usize {
    reap_completed(tasks);
    tasks.with(|tasks| tasks.len())
  }
}

async fn join_next(
  join_set: &impl TaskSet,
) -> Option<Result<(), JoinError>> {
  poll_fn(|cx| join_set.with(|tasks| tasks.poll_join_next(cx))).await
}

async fn drain_join_set(join_set: &impl TaskSet) {
  while let Some(result) = join_next(join_set).await {
    propagate_task_panic(result);
  }
}

fn reap_completed(join_set: &impl TaskSet) {
  while let Some(result) = join_set.with(|tasks| tasks.try_join_next())
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
