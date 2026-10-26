use std::time::Duration;

use super::tcp_connect::connect;

#[tokio::test]
async fn test_connect_falls_back_to_reachable_address() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let target = listener.local_addr().unwrap();
  let closed =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let closed_addr = closed.local_addr().unwrap();
  drop(closed);
  let stream =
    connect(vec![closed_addr, target], Duration::from_secs(1))
      .await
      .unwrap();
  assert_eq!(stream.peer_addr().unwrap(), target);
  assert!(stream.nodelay().unwrap());
}

#[tokio::test]
async fn test_connect_reports_no_addresses_and_expired_deadline() {
  assert_eq!(
    connect(vec![], Duration::from_secs(1)).await.unwrap_err().kind(),
    std::io::ErrorKind::InvalidInput
  );
  assert_eq!(
    connect(vec!["127.0.0.1:1".parse().unwrap()], Duration::ZERO)
      .await
      .unwrap_err()
      .kind(),
    std::io::ErrorKind::TimedOut
  );
}

#[tokio::test]
async fn test_connect_rejects_unrepresentable_timeout() {
  let address = "127.0.0.1:1".parse().unwrap();
  let result = super::tcp_connect::connect(
    vec![address],
    std::time::Duration::MAX,
  )
  .await;
  assert_eq!(
    result.unwrap_err().kind(),
    std::io::ErrorKind::InvalidInput
  );
}
