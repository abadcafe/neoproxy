//! Public-contract tests for worker transport release coordination.

use std::time::Duration;

use crate::shutdown::ShutdownHandle;
use crate::worker_shutdown::participants;

#[tokio::test]
async fn test_finish_waits_for_other_workers() {
  let shutdown = ShutdownHandle::new();
  let mut workers = participants(2, shutdown.clone());
  let mut first = workers.pop().unwrap();
  let mut second = workers.pop().unwrap();
  let mut waiting = Box::pin(first.finish());
  assert!(
    tokio::time::timeout(Duration::from_millis(10), &mut waiting)
      .await
      .is_err()
  );
  assert!(shutdown.is_shutdown());
  tokio::join!(waiting, second.finish());
}

#[tokio::test]
async fn test_drop_releases_failed_or_unstarted_worker() {
  let shutdown = ShutdownHandle::new();
  let mut workers = participants(2, shutdown.clone());
  let mut first = workers.pop().unwrap();
  drop(workers);
  assert!(shutdown.is_shutdown());
  tokio::time::timeout(Duration::from_secs(1), first.finish())
    .await
    .unwrap();
}

#[tokio::test]
async fn test_finish_can_be_waited_again_after_cancellation() {
  let mut workers = participants(2, ShutdownHandle::new());
  let mut first = workers.pop().unwrap();
  assert!(
    tokio::time::timeout(Duration::from_millis(10), first.finish())
      .await
      .is_err()
  );
  drop(workers);
  first.finish().await;
  first.finish().await;
}

#[tokio::test]
async fn test_drop_during_panic_notifies_and_releases_peers() {
  let shutdown = ShutdownHandle::new();
  let mut workers = participants(2, shutdown.clone());
  let mut surviving = workers.pop().unwrap();
  let failed = workers.pop().unwrap();
  let thread = std::thread::spawn(move || {
    let _worker = failed;
    // Deliberately exercise unwinding; programming panics must remain
    // observable while their lifecycle guard releases surviving peers.
    panic!("intentional worker failure");
  });
  assert!(thread.join().is_err());
  assert!(shutdown.is_shutdown());
  surviving.finish().await;
}
