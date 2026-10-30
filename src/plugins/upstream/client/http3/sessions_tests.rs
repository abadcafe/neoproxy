use std::sync::Arc;
use std::time::Duration;

use super::sessions::Store;
use crate::task_tracker::background::TaskTracker;

#[tokio::test(start_paused = true)]
async fn test_capacity_release_wakes_waiter_without_maintenance_tick() {
  let tasks = Arc::new(TaskTracker::new());
  let store = Store::new(
    1,
    Duration::from_secs(60),
    crate::header_limits::ResponseLimits::default().limits(),
    tasks.clone(),
  );
  let bucket = store.bucket(
    "127.0.0.1:443".parse().unwrap(),
    &tokio::runtime::Handle::current(),
  );
  let permit = bucket.reserve().unwrap();
  let waiting = bucket.wait_capacity();
  tokio::pin!(waiting);
  assert!(futures::poll!(&mut waiting).is_pending());
  drop(permit);
  let started = tokio::time::Instant::now();
  let permit = waiting.await.unwrap();
  assert_eq!(started.elapsed(), Duration::ZERO);
  store.close();
  assert!(bucket.wait_capacity().await.is_none());
  drop(permit);
  tasks.wait_shutdown().await;
}
