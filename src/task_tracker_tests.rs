//! Black-box tests for the tracker module.

use std::future::Future;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::task_tracker::TaskTracker;

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
fn test_task_tracker_new() {
  let tracker = TaskTracker::new();
  assert_eq!(tracker.active_count(), 0);
}

#[tokio::test]
async fn test_task_tracker_register() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = TaskTracker::new();
      tracker.register(std::future::pending());
      tokio::task::yield_now().await;
      assert_eq!(tracker.active_count(), 1);
    })
    .await;
}

#[tokio::test]
async fn test_task_tracker_register_multiple() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = TaskTracker::new();
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
      let tracker = TaskTracker::new();
      for _ in 0..100 {
        tracker.register(async {});
        tokio::task::yield_now().await;
        assert_eq!(tracker.active_count(), 0);
      }
    })
    .await;
}

#[tokio::test]
async fn test_task_tracker_shutdown() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = TaskTracker::new();
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
async fn test_task_tracker_abort_all() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = TaskTracker::new();
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
fn test_task_tracker_abort_all_empty() {
  let tracker = TaskTracker::new();
  tracker.abort_all();
  assert_eq!(tracker.active_count(), 0);
}

#[tokio::test]
async fn test_register_returns_abort_handle() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = TaskTracker::new();
      let handle = tracker.register(async {
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
async fn test_register_handle_not_finished_while_running() {
  let local_set = tokio::task::LocalSet::new();
  local_set
    .run_until(async {
      let tracker = TaskTracker::new();
      let handle = tracker.register(async {
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
      let tracker = TaskTracker::new();
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
      let tracker = TaskTracker::new();
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
async fn test_wait_shutdown_propagates_task_panic() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = TaskTracker::new();
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
async fn test_graceful_shutdown_waits_for_async_cleanup() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = TaskTracker::new();
      let shutdown = tracker.shutdown_handle();
      let (started, ready) = tokio::sync::oneshot::channel();
      let (release, released) = tokio::sync::oneshot::channel();
      let cleaned = Rc::new(std::cell::Cell::new(false));
      let result = cleaned.clone();
      tracker.register(async move {
        shutdown.notified().await;
        started.send(()).unwrap();
        released.await.unwrap();
        result.set(true);
      });
      let closing = tracker.graceful_shutdown(Duration::from_secs(1));
      tokio::pin!(closing);
      tokio::select! {
        _ = &mut closing => panic!("shutdown skipped async cleanup"),
        result = ready => result.unwrap(),
      }
      assert!(!cleaned.get());
      release.send(()).unwrap();
      closing.await;
      assert!(cleaned.get());
      assert_eq!(tracker.active_count(), 0);
    })
    .await;
}

#[tokio::test(start_paused = true)]
async fn test_graceful_shutdown_aborts_only_after_deadline() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = TaskTracker::new();
      let shutdown = tracker.shutdown_handle();
      let (alive, mut dropped) = tokio::sync::oneshot::channel::<()>();
      tracker.register(async move {
        let _alive = alive;
        shutdown.notified().await;
        std::future::pending::<()>().await;
      });
      let closing = tracker.graceful_shutdown(Duration::from_secs(1));
      tokio::pin!(closing);
      assert!(futures::poll!(&mut closing).is_pending());
      tokio::time::advance(Duration::from_millis(999)).await;
      assert!(futures::poll!(&mut closing).is_pending());
      assert!(dropped.try_recv().is_err());
      tokio::time::advance(Duration::from_millis(1)).await;
      closing.await;
      assert!(dropped.await.is_err());
      assert_eq!(tracker.active_count(), 0);
    })
    .await;
}
#[tokio::test]
async fn test_monitor_observes_registration_after_waiting_on_empty_tracker()
 {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker =
        std::rc::Rc::new(crate::task_tracker::TaskTracker::new());
      let tasks = tracker.clone();
      let monitor =
        tokio::task::spawn_local(async move { tasks.monitor().await });
      tokio::task::yield_now().await;
      tracker.register(async { panic!("late task programming error") });
      let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        monitor,
      )
      .await
      .unwrap()
      .unwrap_err();
      assert!(error.is_panic());
    })
    .await;
}

#[derive(Default)]
struct MonitorWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for MonitorWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  }
}

#[test]
fn test_monitor_stays_pending_when_empty_and_after_shutdown() {
  let tracker = TaskTracker::new();
  let mut monitor = Box::pin(tracker.monitor());
  let mut context =
    std::task::Context::from_waker(std::task::Waker::noop());
  assert!(monitor.as_mut().poll(&mut context).is_pending());
  tracker.shutdown();
  assert!(monitor.as_mut().poll(&mut context).is_pending());
}

#[tokio::test]
async fn test_monitor_registration_wakes_latest_empty_waiter() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = TaskTracker::new();
      let first = Arc::new(MonitorWake::default());
      let latest = Arc::new(MonitorWake::default());
      let first_waker = std::task::Waker::from(first.clone());
      let latest_waker = std::task::Waker::from(latest.clone());
      let mut monitor = Box::pin(tracker.monitor());
      assert!(
        monitor
          .as_mut()
          .poll(&mut std::task::Context::from_waker(&first_waker))
          .is_pending()
      );
      assert!(
        monitor
          .as_mut()
          .poll(&mut std::task::Context::from_waker(&latest_waker))
          .is_pending()
      );
      tracker.register(std::future::pending());
      assert_eq!(first.0.load(std::sync::atomic::Ordering::SeqCst), 0);
      assert_eq!(latest.0.load(std::sync::atomic::Ordering::SeqCst), 1);
      drop(monitor);
      tracker.abort_all();
      tracker.drain().await;
    })
    .await;
}

#[tokio::test]
async fn test_monitor_collects_completed_tasks_and_waits_for_next_registration()
 {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = TaskTracker::new();
      tracker.register(async {});
      let wake = Arc::new(MonitorWake::default());
      let waker = std::task::Waker::from(wake.clone());
      let mut context = std::task::Context::from_waker(&waker);
      let mut monitor = Box::pin(tracker.monitor());
      assert!(monitor.as_mut().poll(&mut context).is_pending());
      tokio::task::yield_now().await;
      assert!(wake.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
      assert!(monitor.as_mut().poll(&mut context).is_pending());
      assert_eq!(tracker.active_count(), 0);
      wake.0.store(0, std::sync::atomic::Ordering::SeqCst);
      tracker.register(std::future::pending());
      assert_eq!(wake.0.load(std::sync::atomic::Ordering::SeqCst), 1);
      drop(monitor);
      tracker.abort_all();
      tracker.drain().await;
    })
    .await;
}

#[tokio::test]
async fn test_monitor_can_be_replaced_before_shutdown_drain() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let tracker = TaskTracker::new();
      let first = Arc::new(MonitorWake::default());
      let latest = Arc::new(MonitorWake::default());
      let first_waker = std::task::Waker::from(first.clone());
      let latest_waker = std::task::Waker::from(latest.clone());
      let mut monitor = Box::pin(tracker.monitor());
      assert!(
        monitor
          .as_mut()
          .poll(&mut std::task::Context::from_waker(&first_waker))
          .is_pending()
      );
      drop(monitor);
      let mut replacement = Box::pin(tracker.monitor());
      assert!(
        replacement
          .as_mut()
          .poll(&mut std::task::Context::from_waker(&latest_waker))
          .is_pending()
      );
      let shutdown = tracker.shutdown_handle();
      tracker.register(async move {
        shutdown.notified().await;
      });
      assert_eq!(first.0.load(std::sync::atomic::Ordering::SeqCst), 0);
      assert_eq!(latest.0.load(std::sync::atomic::Ordering::SeqCst), 1);
      drop(replacement);
      tracker.graceful_shutdown(Duration::from_secs(1)).await;
      assert_eq!(tracker.active_count(), 0);
    })
    .await;
}
