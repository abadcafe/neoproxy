//! Public lifetime contracts for UDP capsule bridge tasks.
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::task_tracker::TaskTracker;

#[tokio::test]
async fn test_udp_bridge_shutdown_notifies_and_joins_without_peer_traffic()
 {
  tokio::task::LocalSet::new()
    .run_until(async {
      let socket =
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
      let tracker = TaskTracker::new();
      let mut io = crate::connect_udp::direct::connect(
        socket.local_addr().unwrap(),
        &tracker,
      )
      .await
      .unwrap();
      tracker.graceful_shutdown(Duration::from_secs(1)).await;
      let mut bytes = Vec::new();
      io.read_to_end(&mut bytes).await.unwrap();
      assert!(bytes.is_empty());
      assert_eq!(tracker.active_count(), 0);
    })
    .await;
}

#[tokio::test]
async fn test_udp_bridge_fin_waits_for_accepted_capsule_delivery() {
  tokio::task::LocalSet::new()
    .run_until(async {
      let socket =
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
      let tracker = TaskTracker::new();
      let mut io = crate::connect_udp::direct::connect(
        socket.local_addr().unwrap(),
        &tracker,
      )
      .await
      .unwrap();
      io.write_all(&crate::connect_udp::capsule::encode(
        b"last-packet",
      ))
      .await
      .unwrap();
      tokio::time::timeout(Duration::from_secs(1), io.shutdown())
        .await
        .unwrap()
        .unwrap();
      let mut bytes = [0; 32];
      let count = tokio::time::timeout(
        Duration::from_secs(1),
        socket.recv(&mut bytes),
      )
      .await
      .unwrap()
      .unwrap();
      assert_eq!(&bytes[..count], b"last-packet");
      tracker.wait_shutdown().await;
      assert_eq!(tracker.active_count(), 0);
    })
    .await;
}
