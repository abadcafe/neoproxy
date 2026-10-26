use std::net::SocketAddr;
use std::time::Duration;

use crate::address_race::{RaceError, connect};

#[tokio::test(start_paused = true)]
async fn test_connect_interleaves_families_before_exhausting_first_family()
 {
  let start = tokio::time::Instant::now();
  let reachable: SocketAddr = "127.0.0.1:8123".parse().unwrap();
  let result = connect(
    vec![
      "[::1]:8123".parse().unwrap(),
      "[::2]:8123".parse().unwrap(),
      reachable,
    ],
    Duration::from_millis(400),
    |address| async move {
      if address.is_ipv6() {
        std::future::pending::<()>().await;
      }
      Ok::<_, ()>(address)
    },
  )
  .await;
  assert_eq!(result.unwrap(), reachable);
  assert_eq!(start.elapsed(), Duration::from_millis(250));
}

#[tokio::test(start_paused = true)]
async fn test_connect_attempts_each_duplicate_address_once() {
  let count =
    std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let address: SocketAddr = "127.0.0.1:8123".parse().unwrap();
  let result = connect(
    vec![address, address],
    Duration::from_secs(1),
    |address| {
      count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      std::future::ready(Err::<(), _>(address))
    },
  )
  .await;
  assert!(matches!(result, Err(RaceError::Failed(_))));
  assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn test_connect_falls_back_without_waiting_for_stalled_candidate()
{
  let first: SocketAddr = "[::1]:8123".parse().unwrap();
  let second = "127.0.0.1:8123".parse().unwrap();
  let result = connect(
    vec![first, second],
    Duration::from_secs(2),
    |address| async move {
      if address.is_ipv6() {
        std::future::pending::<()>().await;
      }
      Ok::<_, ()>(address)
    },
  )
  .await;
  assert_eq!(result.unwrap(), second);
}

#[tokio::test]
async fn test_connect_reports_empty_expired_and_failed_candidates() {
  let attempt = |address| std::future::ready(Err::<(), _>(address));
  let address: SocketAddr = "127.0.0.1:8123".parse().unwrap();
  assert!(matches!(
    connect(vec![], Duration::from_secs(1), attempt).await,
    Err(RaceError::NoAddresses)
  ));
  assert!(matches!(
    connect(vec![address], Duration::ZERO, attempt).await,
    Err(RaceError::Timeout)
  ));
  assert!(matches!(
    connect(vec![address], Duration::MAX, attempt).await,
    Err(RaceError::InvalidDeadline)
  ));
  assert!(
    matches!(connect(vec![address], Duration::from_secs(1), attempt).await, Err(RaceError::Failed(failed)) if failed == address)
  );
}
