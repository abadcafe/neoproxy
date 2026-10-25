//! Black-box tests for the tracker module.

use std::future::Future;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::tracker::StreamTracker;

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    self.0.lock().unwrap().extend_from_slice(bytes);
    Ok(bytes.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl LogBuffer {
  fn output(&self) -> String {
    String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
  }
}

fn capture_logs() -> (LogBuffer, tracing::subscriber::DefaultGuard) {
  let buffer = LogBuffer::default();
  let writer = buffer.clone();
  let subscriber = tracing_subscriber::fmt()
    .with_writer(move || writer.clone())
    .without_time()
    .with_ansi(false)
    .with_max_level(tracing::Level::ERROR)
    .finish();
  (buffer, tracing::subscriber::set_default(subscriber))
}

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
      tracker.register(std::future::pending());
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
      tracker.register(std::future::pending());
      tracker.register(std::future::pending());
      tracker.register(std::future::pending());
      tokio::task::yield_now().await;
      assert_eq!(tracker.active_count(), 3);
    })
    .await;
}

#[tokio::test]
async fn test_register_reclaims_completed_tasks() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = StreamTracker::new();
      for _ in 0..100 {
        tracker.register(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 0);
      }
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
        "AbortHandle should NOT report is_finished while task is \
         running"
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

const TASK_PANIC: &str = "tracked task programming error";

fn panicking_task()
-> (impl Future<Output = ()>, tokio::sync::oneshot::Receiver<()>) {
  let (started, completed) = tokio::sync::oneshot::channel();
  let task = async move {
    started.send(()).unwrap();
    // Inject a programming error deliberately. Collecting this task
    // must resume this exact payload instead of logging and
    // returning success.
    std::panic::panic_any(TASK_PANIC);
  };
  (task, completed)
}

async fn assert_original_panic(task: tokio::task::JoinHandle<()>) {
  // Observe the collector's resumed panic through Tokio's public join
  // boundary; no application code catches or downgrades the panic.
  let error = tokio::time::timeout(Duration::from_secs(1), task)
    .await
    .unwrap()
    .unwrap_err();
  assert!(error.is_panic());
  let payload = error.into_panic();
  assert_eq!(payload.downcast_ref::<&str>(), Some(&TASK_PANIC));
}

#[tokio::test]
async fn test_active_count_propagates_task_panic() {
  let (logs, _guard) = capture_logs();
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = StreamTracker::new();
      let (task, completed) = panicking_task();
      tracker.register(task);
      completed.await.unwrap();
      let collector = tokio::task::spawn_local(async move {
        tracker.active_count();
      });
      assert_original_panic(collector).await;
    })
    .await;
  let output = logs.output();
  assert!(output.contains(TASK_PANIC), "{output}");
  assert!(output.contains("task_id="), "{output}");
}

#[tokio::test]
async fn test_register_propagates_task_panic() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = StreamTracker::new();
      let (task, completed) = panicking_task();
      tracker.register(task);
      completed.await.unwrap();
      let collector = tokio::task::spawn_local(async move {
        tracker.register(async {});
      });
      assert_original_panic(collector).await;
    })
    .await;
}

#[tokio::test]
async fn test_register_connection_propagates_task_panic() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = StreamTracker::new();
      let (task, completed) = panicking_task();
      tracker.register_connection(task);
      completed.await.unwrap();
      let collector = tokio::task::spawn_local(async move {
        tracker.register_connection(async {});
      });
      assert_original_panic(collector).await;
    })
    .await;
}

#[tokio::test]
async fn test_wait_shutdown_propagates_stream_panic() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = StreamTracker::new();
      let (task, completed) = panicking_task();
      tracker.register(task);
      completed.await.unwrap();
      let collector = tokio::task::spawn_local(async move {
        tracker.wait_shutdown().await;
      });
      assert_original_panic(collector).await;
    })
    .await;
}

#[tokio::test]
async fn test_wait_shutdown_propagates_connection_panic() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = StreamTracker::new();
      let (task, completed) = panicking_task();
      tracker.register_connection(task);
      completed.await.unwrap();
      let collector = tokio::task::spawn_local(async move {
        tracker.wait_shutdown().await;
      });
      assert_original_panic(collector).await;
    })
    .await;
}
