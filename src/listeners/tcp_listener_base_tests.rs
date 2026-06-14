//! Tests for TcpListenerBase.

use std::pin::Pin;
use std::future::Future;
use std::rc::Rc;
use std::cell::Cell;

use anyhow::Result;

use super::tcp_listener_base::TcpListenerBase;

#[test]
fn test_tcp_listener_base_new() {
  let base = TcpListenerBase::new();
  assert_eq!(base.stream_tracker().active_count(), 0);
}

#[test]
fn test_tcp_listener_base_default_timeout() {
  let base = TcpListenerBase::new();
  assert_eq!(
    base.graceful_shutdown_timeout,
    super::tcp_listener_base::LISTENER_SHUTDOWN_TIMEOUT
  );
}

#[tokio::test]
async fn test_tcp_listener_base_start_with_empty_tasks() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let base = TcpListenerBase::new();
      let tasks: Vec<Pin<Box<dyn Future<Output = Result<()>>>>> =
        Vec::new();

      let fut = base.start_with_tasks(tasks);
      let handle = tokio::task::spawn_local(fut);
      // Yield to let the future start executing
      tokio::task::yield_now().await;
      // Trigger shutdown
      base.stop();

      let result = handle.await.unwrap();
      assert!(result.is_ok());
    })
    .await;
}

#[tokio::test]
async fn test_tcp_listener_base_start_with_single_task() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let base = TcpListenerBase::new();
      let task: Pin<Box<dyn Future<Output = Result<()>>>> =
        Box::pin(async { Ok(()) });
      let tasks = vec![task];

      let fut = base.start_with_tasks(tasks);
      let handle = tokio::task::spawn_local(fut);
      tokio::task::yield_now().await;
      // Trigger shutdown
      base.stop();

      let result = handle.await.unwrap();
      assert!(result.is_ok());
    })
    .await;
}

#[tokio::test]
async fn test_tcp_listener_base_start_with_multiple_tasks() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let base = TcpListenerBase::new();
      let tasks: Vec<Pin<Box<dyn Future<Output = Result<()>>>>> = vec![
        Box::pin(async { Ok(()) }),
        Box::pin(async { Ok(()) }),
        Box::pin(async { Ok(()) }),
      ];

      let fut = base.start_with_tasks(tasks);
      let handle = tokio::task::spawn_local(fut);
      tokio::task::yield_now().await;
      // Trigger shutdown
      base.stop();

      let result = handle.await.unwrap();
      assert!(result.is_ok());
    })
    .await;
}

#[tokio::test]
async fn test_tcp_listener_base_start_with_failing_task() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let base = TcpListenerBase::new();
      let tasks: Vec<Pin<Box<dyn Future<Output = Result<()>>>>> =
        vec![Box::pin(async {
          anyhow::bail!("test error")
        })];

      let fut = base.start_with_tasks(tasks);
      let handle = tokio::task::spawn_local(fut);
      tokio::task::yield_now().await;
      // Trigger shutdown
      base.stop();

      // The future should still complete (errors are logged, not
      // propagated)
      let result = handle.await.unwrap();
      assert!(result.is_ok());
    })
    .await;
}

#[test]
fn test_tcp_listener_base_stop_triggers_shutdown() {
  let base = TcpListenerBase::new();
  let handle = base.shutdown_handle();

  assert!(!handle.is_shutdown());
  base.stop();
  assert!(handle.is_shutdown());
}

#[tokio::test]
async fn test_tcp_listener_base_shutdown_handle_shares_state() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let base = TcpListenerBase::new();
      let handle1 = base.shutdown_handle();
      let handle2 = base.shutdown_handle();

      assert!(!handle1.is_shutdown());
      assert!(!handle2.is_shutdown());

      base.stop();

      assert!(handle1.is_shutdown());
      assert!(handle2.is_shutdown());
    })
    .await;
}

#[tokio::test]
async fn test_tcp_listener_base_tasks_receive_shutdown() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let base = TcpListenerBase::new();
      let completed = Rc::new(Cell::new(false));
      let completed_clone = completed.clone();

      let shutdown_handle = base.shutdown_handle();
      let task: Pin<Box<dyn Future<Output = Result<()>>>> =
        Box::pin(async move {
          shutdown_handle.notified().await;
          completed_clone.set(true);
          Ok(())
        });
      let tasks = vec![task];

      let fut = base.start_with_tasks(tasks);
      let handle = tokio::task::spawn_local(fut);
      tokio::task::yield_now().await;
      // Trigger shutdown
      base.stop();

      let result = handle.await.unwrap();
      assert!(result.is_ok());
      assert!(completed.get());
    })
    .await;
}
