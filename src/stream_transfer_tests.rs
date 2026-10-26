//! Public transfer accounting includes partial progress on termination.
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::stream::{TransferEnd, TransferProgress, run_tunnel};

#[tokio::test]
async fn test_run_tunnel_counts_both_directions_until_eof() {
  let (client, mut left) = tokio::io::duplex(64);
  let (target, mut right) = tokio::io::duplex(64);
  let progress = TransferProgress::new();
  let copy = run_tunnel(
    client,
    target,
    crate::shutdown::ShutdownHandle::new(),
    Duration::from_secs(1),
    progress.clone(),
  );
  let exchange = async {
    left.write_all(b"request").await.unwrap();
    left.shutdown().await.unwrap();
    let mut request = Vec::new();
    right.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");
    right.write_all(b"response").await.unwrap();
    right.shutdown().await.unwrap();
    let mut response = Vec::new();
    left.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response");
  };
  let (end, ()) = tokio::join!(copy, exchange);
  assert!(matches!(end, TransferEnd::Completed));
  let totals = progress.totals();
  assert_eq!(totals.client_to_upstream, 7);
  assert_eq!(totals.upstream_to_client, 8);
}

#[tokio::test(start_paused = true)]
async fn test_run_tunnel_idle_timeout_keeps_partial_byte_counts() {
  let (client, mut left) = tokio::io::duplex(64);
  let (target, mut right) = tokio::io::duplex(64);
  let progress = TransferProgress::new();
  let mut copy = std::pin::pin!(run_tunnel(
    client,
    target,
    crate::shutdown::ShutdownHandle::new(),
    Duration::from_millis(100),
    progress.clone()
  ));
  left.write_all(b"partial").await.unwrap();
  assert!(futures::poll!(&mut copy).is_pending());
  let mut bytes = [0; 7];
  right.read_exact(&mut bytes).await.unwrap();
  tokio::time::advance(Duration::from_millis(101)).await;
  assert!(matches!(copy.await, TransferEnd::IdleTimeout));
  assert_eq!(progress.totals().client_to_upstream, 7);
  assert_eq!(progress.totals().upstream_to_client, 0);
}

#[tokio::test]
async fn test_run_tunnel_shutdown_keeps_partial_progress() {
  let (client, mut left) = tokio::io::duplex(64);
  let (target, mut right) = tokio::io::duplex(64);
  let progress = TransferProgress::new();
  let shutdown = crate::shutdown::ShutdownHandle::new();
  let mut copy = Box::pin(run_tunnel(
    client,
    target,
    shutdown.clone(),
    Duration::from_secs(60),
    progress.clone(),
  ));
  left.write_all(b"partial").await.unwrap();
  assert!(futures::poll!(&mut copy).is_pending());
  let mut bytes = [0; 7];
  right.read_exact(&mut bytes).await.unwrap();
  shutdown.shutdown();
  assert!(matches!(copy.await, TransferEnd::Shutdown));
  assert_eq!(progress.totals().client_to_upstream, 7);
}

#[tokio::test]
async fn test_run_tunnel_drop_keeps_progress_for_completion_owner() {
  let (client, mut left) = tokio::io::duplex(64);
  let (target, mut right) = tokio::io::duplex(64);
  let progress = TransferProgress::new();
  let mut copy = Box::pin(run_tunnel(
    client,
    target,
    crate::shutdown::ShutdownHandle::new(),
    Duration::from_secs(60),
    progress.clone(),
  ));
  left.write_all(b"partial").await.unwrap();
  assert!(futures::poll!(&mut copy).is_pending());
  let mut bytes = [0; 7];
  right.read_exact(&mut bytes).await.unwrap();
  drop(copy);
  assert_eq!(progress.totals().client_to_upstream, 7);
  assert_eq!(right.read(&mut bytes).await.unwrap(), 0);
}
