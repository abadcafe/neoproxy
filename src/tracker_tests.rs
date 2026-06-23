//! Black-box tests for the tracker module.

use std::rc::Rc;
use std::time::Duration;

use crate::tracker::StreamTracker;

#[test]
fn test_stream_tracker_new() {
  let tracker = StreamTracker::new();
  assert_eq!(tracker.active_count(), 0);
}

#[tokio::test]
async fn test_stream_tracker_register() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = StreamTracker::new();
      tracker.register(async {});
      tokio::task::yield_now().await;
      assert_eq!(tracker.active_count(), 1);
    })
    .await;
}

#[tokio::test]
async fn test_stream_tracker_register_multiple() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = StreamTracker::new();
      tracker.register(async {});
      tracker.register(async {});
      tracker.register(async {});
      tokio::task::yield_now().await;
      assert_eq!(tracker.active_count(), 3);
    })
    .await;
}

#[tokio::test]
async fn test_stream_tracker_shutdown() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = StreamTracker::new();
      let shutdown_handle = tracker.shutdown_handle();

      let notified = Rc::new(std::cell::Cell::new(false));
      let notified_clone = notified.clone();
      tracker.register(async move {
        shutdown_handle.notified().await;
        notified_clone.set(true);
      });
      tokio::task::yield_now().await;

      tracker.shutdown();
      tracker.wait_shutdown().await;
      assert_eq!(tracker.active_count(), 0);
      assert!(notified.get());
    })
    .await;
}

#[tokio::test]
async fn test_stream_tracker_abort_all() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = StreamTracker::new();
      tracker.register(async {
        std::future::pending::<()>().await;
      });
      tokio::task::yield_now().await;
      assert_eq!(tracker.active_count(), 1);

      tracker.abort_all();
      tracker.wait_shutdown().await;
      assert_eq!(tracker.active_count(), 0);
    })
    .await;
}

#[test]
fn test_stream_tracker_abort_all_empty() {
  let tracker = StreamTracker::new();
  tracker.abort_all();
  assert_eq!(tracker.active_count(), 0);
}

#[tokio::test]
async fn test_register_connection_returns_abort_handle() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = StreamTracker::new();
      let handle = tracker.register_connection(async {
        // empty task completes immediately
      });
      // Yield to let the task run
      tokio::task::yield_now().await;
      assert!(
        handle.is_finished(),
        "AbortHandle should report is_finished after task completes"
      );
    })
    .await;
}

#[tokio::test]
async fn test_register_connection_handle_not_finished_while_running() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = StreamTracker::new();
      let handle = tracker.register_connection(async {
        tokio::time::sleep(Duration::from_millis(100)).await;
      });
      // Should NOT be finished yet
      assert!(
        !handle.is_finished(),
        "AbortHandle should NOT report is_finished while task is running"
      );
      // Wait for completion
      tokio::time::sleep(Duration::from_millis(200)).await;
      assert!(
        handle.is_finished(),
        "AbortHandle should report is_finished after task completes"
      );
    })
    .await;
}
