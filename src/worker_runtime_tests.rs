//! Black-box contracts for worker-local runtime ownership.

use std::sync::mpsc;
use std::time::Duration;

use crate::worker_runtime::run;

#[test]
fn test_run_releases_worker_without_waiting_for_blocking_io() {
  let (started, started_rx) = mpsc::channel();
  let (release, release_rx) = mpsc::channel();
  let (completed, completed_rx) = mpsc::channel();
  let worker = std::thread::spawn(move || {
    let result = run(async move {
      tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        release_rx.recv().unwrap();
      });
      tokio::task::yield_now().await;
      42
    });
    completed.send(result).unwrap();
  });
  started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
  let result = completed_rx.recv_timeout(Duration::from_millis(500));
  // Release even on failure, so the failing contract never strands a
  // test thread. Real getaddrinfo can remain blocked far longer than
  // the listener and plugin shutdown budgets.
  release.send(()).unwrap();
  worker.join().unwrap();
  assert_eq!(result.unwrap().unwrap(), 42);
}

#[test]
fn test_run_drives_local_tasks_and_drops_them_at_worker_exit() {
  let (dropped, dropped_rx) = mpsc::channel::<()>();
  let result = run(async move {
    let value = std::rc::Rc::new(17);
    let task = tokio::task::spawn_local(async move { *value });
    let observed = task.await.unwrap();
    tokio::task::spawn_local(async move {
      let _owned = dropped;
      std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    observed
  })
  .unwrap();
  assert_eq!(result, 17);
  assert!(matches!(dropped_rx.recv(), Err(mpsc::RecvError)));
}
