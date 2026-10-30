//! Public cancellation contracts for capsule bridge ownership.
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::bridge::spawn;
use crate::task_tracker::TaskTracker;

#[tokio::test]
async fn test_spawn_drop_cancels_backpressured_handler() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tasks = TaskTracker::new();
      let (started, ready) = tokio::sync::oneshot::channel();
      let io = spawn(&tasks, move |mut transport, _| async move {
        transport.write_all(&vec![0; 131072]).await.unwrap();
        started.send(()).unwrap();
        let _ = transport.write_all(b"blocked").await;
        std::future::pending::<()>().await;
      });
      ready.await.unwrap();
      drop(io);
      tokio::time::timeout(
        Duration::from_secs(1),
        tasks.wait_shutdown(),
      )
      .await
      .unwrap();
      assert_eq!(tasks.active_count(), 0);
    })
    .await;
}

#[tokio::test]
async fn test_spawn_shutdown_cancels_backpressured_handler() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tasks = TaskTracker::new();
      let (started, ready) = tokio::sync::oneshot::channel();
      let _io = spawn(&tasks, move |mut transport, _| async move {
        transport.write_all(&vec![0; 131072]).await.unwrap();
        started.send(()).unwrap();
        let _ = transport.write_all(b"blocked").await;
      });
      ready.await.unwrap();
      tasks.shutdown();
      tokio::time::timeout(
        Duration::from_secs(1),
        tasks.wait_shutdown(),
      )
      .await
      .unwrap();
      assert_eq!(tasks.active_count(), 0);
    })
    .await;
}
