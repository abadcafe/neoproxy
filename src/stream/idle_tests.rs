use std::time::Duration;

use super::idle::IdleDeadline;

#[tokio::test(start_paused = true)]
async fn test_is_expired_at_exact_deadline_and_after_submillisecond_activity()
 {
  let idle_deadline = IdleDeadline::new(Duration::from_nanos(100));
  assert!(!idle_deadline.is_expired());
  tokio::time::advance(Duration::from_nanos(100)).await;
  assert!(idle_deadline.is_expired());
  idle_deadline.record_activity();
  assert!(!idle_deadline.is_expired());
  assert_eq!(
    idle_deadline.deadline(),
    tokio::time::Instant::now() + Duration::from_nanos(100)
  );
}

#[test]
fn test_new_deadline_is_not_expired() {
  let idle_deadline = IdleDeadline::new(Duration::from_secs(30));
  assert!(
    !idle_deadline.is_expired(),
    "Newly created deadline should not be expired"
  );
}

#[test]
fn test_record_activity_advances_deadline() {
  let idle_deadline = IdleDeadline::new(Duration::from_secs(30));
  let d1 = idle_deadline.deadline();
  std::thread::sleep(std::time::Duration::from_millis(50));
  idle_deadline.record_activity();
  let d2 = idle_deadline.deadline();
  assert!(
    d2 > d1,
    "After activity, deadline should advance: {d2:?} <= {d1:?}"
  );
}

#[test]
fn test_record_activity_invalidates_previous_deadline() {
  let idle_deadline = IdleDeadline::new(Duration::from_millis(200));

  assert!(!idle_deadline.is_expired());

  std::thread::sleep(std::time::Duration::from_millis(150));
  idle_deadline.record_activity();

  assert!(
    !idle_deadline.is_expired(),
    "Deadline should not expire immediately after activity"
  );

  std::thread::sleep(std::time::Duration::from_millis(50));
  assert!(
    !idle_deadline.is_expired(),
    "50ms after activity should not expire a 200ms deadline"
  );

  std::thread::sleep(std::time::Duration::from_millis(200));
  assert!(
    idle_deadline.is_expired(),
    "200ms after activity should expire a 200ms deadline"
  );
}
