use std::time::Duration;

use super::idle::IdleTracker;

#[tokio::test(start_paused = true)]
async fn test_is_idle_at_exact_deadline_and_after_submillisecond_activity()
 {
  let tracker = IdleTracker::new(Duration::from_nanos(100));
  assert!(!tracker.is_idle());
  tokio::time::advance(Duration::from_nanos(100)).await;
  assert!(tracker.is_idle());
  tracker.touch();
  assert!(!tracker.is_idle());
  assert_eq!(
    tracker.deadline(),
    tokio::time::Instant::now() + Duration::from_nanos(100)
  );
}

// ============== IdleTracker Tests ==============

#[test]
fn test_idle_tracker_new_not_idle() {
  let tracker = IdleTracker::new(Duration::from_secs(30));
  assert!(
    !tracker.is_idle(),
    "Newly created tracker should not be idle"
  );
}

#[test]
fn test_idle_tracker_touch_updates_deadline() {
  let tracker = IdleTracker::new(Duration::from_secs(30));
  let d1 = tracker.deadline();
  std::thread::sleep(std::time::Duration::from_millis(50));
  tracker.touch();
  let d2 = tracker.deadline();
  assert!(
    d2 > d1,
    "After touch, deadline should advance: {d2:?} <= {d1:?}"
  );
}

#[test]
fn test_idle_tracker_stale_alarm_not_idle() {
  let tracker = IdleTracker::new(Duration::from_millis(200));

  assert!(!tracker.is_idle());

  std::thread::sleep(std::time::Duration::from_millis(150));
  tracker.touch();

  assert!(!tracker.is_idle(), "Should not be idle right after touch");

  std::thread::sleep(std::time::Duration::from_millis(50));
  assert!(
    !tracker.is_idle(),
    "50ms after touch should not be idle with 200ms timeout"
  );

  std::thread::sleep(std::time::Duration::from_millis(200));
  assert!(
    tracker.is_idle(),
    "200ms after touch should be idle with 200ms timeout"
  );
}
