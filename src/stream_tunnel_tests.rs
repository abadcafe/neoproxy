//! Public tunnel contracts when H3 send/finish is backpressured.

use std::future::{Future, pending};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::h3_stream::{H3BidirectionalStream, H3Recv, H3Send};
use crate::shutdown::ShutdownHandle;
use crate::stream::run_tunnel;

struct StalledFinish;

impl H3Send for StalledFinish {
  async fn send_data(&mut self, _: Bytes) -> std::io::Result<()> {
    Ok(())
  }

  fn finish(
    &mut self,
  ) -> impl Future<Output = std::io::Result<()>> + Send + Sync {
    pending()
  }
}

struct StalledSend;

impl H3Send for StalledSend {
  fn send_data(
    &mut self,
    _: Bytes,
  ) -> impl Future<Output = std::io::Result<()>> + Send + Sync {
    pending()
  }

  async fn finish(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

struct EofRecv;

impl H3Recv for EofRecv {
  fn poll_recv_data(
    &mut self,
    _: &mut Context<'_>,
  ) -> Poll<std::io::Result<Option<Bytes>>> {
    Poll::Ready(Ok(None))
  }
}

async fn assert_stalled_tunnel_times_out<S: H3Send>(
  send: S,
  payload: &[u8],
) {
  let (target, mut peer) = tokio::io::duplex(64);
  peer.write_all(payload).await.unwrap();
  drop(peer);
  let stream = H3BidirectionalStream::new(send, EofRecv);
  let mut tunnel = std::pin::pin!(run_tunnel(
    stream,
    target,
    ShutdownHandle::new(),
    Duration::from_millis(100),
    "stalled-h3",
  ));
  assert!(futures::poll!(&mut tunnel).is_pending());
  tokio::time::advance(Duration::from_millis(99)).await;
  assert!(futures::poll!(&mut tunnel).is_pending());
  tokio::time::advance(Duration::from_millis(2)).await;
  assert!(
    futures::poll!(&mut tunnel).is_ready(),
    "idle deadline failed to stop a stalled H3 tunnel"
  );
}

#[tokio::test(start_paused = true)]
async fn test_run_tunnel_idle_timeout_bounds_stalled_h3_finish_after_both_eofs()
 {
  assert_stalled_tunnel_times_out(StalledFinish, b"").await;
}

#[tokio::test(start_paused = true)]
async fn test_run_tunnel_idle_timeout_bounds_stalled_h3_flush_after_both_eofs()
 {
  assert_stalled_tunnel_times_out(StalledSend, b"unsent-tail").await;
}

#[tokio::test(start_paused = true)]
async fn test_run_tunnel_progress_in_either_direction_extends_shared_deadline()
 {
  let (client, mut left) = tokio::io::duplex(64);
  let (target, mut right) = tokio::io::duplex(64);
  let mut tunnel = std::pin::pin!(run_tunnel(
    client,
    target,
    ShutdownHandle::new(),
    Duration::from_millis(100),
    "active",
  ));
  assert!(futures::poll!(&mut tunnel).is_pending());
  tokio::time::advance(Duration::from_millis(90)).await;
  left.write_all(b"a").await.unwrap();
  assert!(futures::poll!(&mut tunnel).is_pending());
  let mut byte = [0];
  right.read_exact(&mut byte).await.unwrap();
  assert_eq!(byte, *b"a");
  tokio::time::advance(Duration::from_millis(20)).await;
  assert!(futures::poll!(&mut tunnel).is_pending());
  tokio::time::advance(Duration::from_millis(70)).await;
  right.write_all(b"b").await.unwrap();
  assert!(futures::poll!(&mut tunnel).is_pending());
  left.read_exact(&mut byte).await.unwrap();
  assert_eq!(byte, *b"b");
  tokio::time::advance(Duration::from_millis(99)).await;
  assert!(futures::poll!(&mut tunnel).is_pending());
  tokio::time::advance(Duration::from_millis(2)).await;
  assert!(futures::poll!(&mut tunnel).is_ready());
}

#[tokio::test(start_paused = true)]
async fn test_run_tunnel_eof_does_not_refresh_activity_deadline() {
  let (client, mut left) = tokio::io::duplex(64);
  let (target, _right) = tokio::io::duplex(64);
  let mut tunnel = std::pin::pin!(run_tunnel(
    client,
    target,
    ShutdownHandle::new(),
    Duration::from_millis(100),
    "eof",
  ));
  assert!(futures::poll!(&mut tunnel).is_pending());
  tokio::time::advance(Duration::from_millis(90)).await;
  left.shutdown().await.unwrap();
  assert!(futures::poll!(&mut tunnel).is_pending());
  tokio::time::advance(Duration::from_millis(11)).await;
  assert!(futures::poll!(&mut tunnel).is_ready());
}
