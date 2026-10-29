//! Public contracts for cross-thread background task cleanup.
use std::sync::Arc;
use std::time::Duration;

use crate::task_tracker::TaskTracker;

#[tokio::test]
async fn test_shutdown_waits_for_background_cleanup() {
  let tasks = Arc::new(TaskTracker::new());
  let shutdown = tasks.shutdown_handle();
  let (started, ready) = tokio::sync::oneshot::channel();
  let (release, released) = tokio::sync::oneshot::channel();
  tasks.register_on(&tokio::runtime::Handle::current(), async move {
    shutdown.notified().await;
    started.send(()).unwrap();
    released.await.unwrap();
  });
  tasks.shutdown();
  ready.await.unwrap();
  let wait = tasks.wait_shutdown();
  tokio::pin!(wait);
  assert!(futures::poll!(&mut wait).is_pending());
  release.send(()).unwrap();
  wait.await;
}

#[tokio::test(start_paused = true)]
async fn test_finish_aborts_only_uncooperative_background_task() {
  let tasks = TaskTracker::new();
  let (alive, dropped) = tokio::sync::oneshot::channel::<()>();
  tasks.register_on(&tokio::runtime::Handle::current(), async move {
    let _alive = alive;
    std::future::pending::<()>().await;
  });
  tasks.graceful_shutdown(Duration::from_secs(1)).await;
  assert!(dropped.await.is_err());
}
