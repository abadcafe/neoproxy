//! Public I/O timeout contracts, independent of HTTP parser internals.
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::exchange_timeout::{Control, TimedIo, Timeouts};

#[tokio::test(start_paused = true)]
async fn test_read_waits_for_upload_completion() {
  let (io, mut peer) = tokio::io::duplex(32);
  let control = Control::default();
  control.start(Timeouts::default());
  let mut io = hyper_util::rt::TokioIo::new(TimedIo::new(
    hyper_util::rt::TokioIo::new(io),
    control.clone(),
  ));
  let read = async {
    let mut byte = [0];
    io.read_exact(&mut byte).await.unwrap();
    byte
  };
  let upload = async {
    tokio::time::sleep(Duration::from_secs(30)).await;
    control.upload_complete();
    peer.write_all(b"x").await.unwrap();
  };
  let (byte, ()) = tokio::join!(read, upload);
  assert_eq!(byte, *b"x");
}

#[tokio::test(start_paused = true)]
async fn test_read_stall_expires_and_progress_resets() {
  let (io, mut peer) = tokio::io::duplex(32);
  let control = Control::default();
  control.start(Timeouts::default());
  control.response_started();
  let mut io = hyper_util::rt::TokioIo::new(TimedIo::new(
    hyper_util::rt::TokioIo::new(io),
    control,
  ));
  let reader = async {
    let mut byte = [0];
    for _ in 0..3 {
      io.read_exact(&mut byte).await.unwrap();
    }
    assert_eq!(
      io.read_exact(&mut byte).await.unwrap_err().kind(),
      std::io::ErrorKind::TimedOut
    );
  };
  let writer = async {
    for _ in 0..3 {
      tokio::time::sleep(Duration::from_secs(9)).await;
      peer.write_all(b"x").await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(20)).await;
  };
  tokio::join!(reader, writer);
}

#[tokio::test(start_paused = true)]
async fn test_write_stall_expires_and_tunnel_disables_timeouts() {
  let (io, _peer) = tokio::io::duplex(1);
  let control = Control::default();
  control.start(Timeouts::default());
  let mut io = hyper_util::rt::TokioIo::new(TimedIo::new(
    hyper_util::rt::TokioIo::new(io),
    control.clone(),
  ));
  assert_eq!(
    io.write_all(b"abc").await.unwrap_err().kind(),
    std::io::ErrorKind::TimedOut
  );
  control.disable();
  assert!(
    tokio::time::timeout(Duration::from_secs(30), io.write_all(b"x"))
      .await
      .is_err()
  );
}

#[tokio::test(start_paused = true)]
async fn test_trailers_finish_upload_before_body_reports_eof() {
  use http_body_util::BodyExt;
  let frames = futures_util::stream::iter([Ok::<_, anyhow::Error>(
    http_body::Frame::<bytes::Bytes>::trailers(http::HeaderMap::new()),
  )]);
  let body = crate::http_message::RequestBody::new(
    http_body_util::StreamBody::new(frames),
  );
  let control = Control::default();
  control.start(Timeouts::default());
  let mut body =
    super::exchange_timeout::UploadBody::wrap(body, control.clone());
  assert!(body.frame().await.unwrap().unwrap().is_trailers());
  let (io, _peer) = tokio::io::duplex(8);
  let mut io = hyper_util::rt::TokioIo::new(TimedIo::new(
    hyper_util::rt::TokioIo::new(io),
    control,
  ));
  io.flush().await.unwrap();
  assert_eq!(
    io.read_u8().await.unwrap_err().kind(),
    std::io::ErrorKind::TimedOut
  );
}

#[tokio::test(start_paused = true)]
async fn test_reused_connection_uses_new_exchange_policy() {
  let (io, _peer) = tokio::io::duplex(8);
  let control = Control::default();
  let mut io = hyper_util::rt::TokioIo::new(TimedIo::new(
    hyper_util::rt::TokioIo::new(io),
    control.clone(),
  ));
  for seconds in [2, 20] {
    control.start(Timeouts {
      read: Duration::from_secs(seconds),
      send: Duration::from_secs(10),
    });
    control.response_started();
    let started = tokio::time::Instant::now();
    assert_eq!(
      io.read_u8().await.unwrap_err().kind(),
      std::io::ErrorKind::TimedOut
    );
    assert_eq!(started.elapsed(), Duration::from_secs(seconds));
    control.disable();
  }
}

#[tokio::test]
async fn test_cancel_wakes_blocked_exchange_and_closes_without_timeout()
{
  let (io, _peer) = tokio::io::duplex(32);
  let control = Control::default();
  control.start(Timeouts::default());
  let mut io = hyper_util::rt::TokioIo::new(TimedIo::new(
    hyper_util::rt::TokioIo::new(io),
    control.clone(),
  ));
  let read = async {
    let mut byte = [0];
    let error = io.read_exact(&mut byte).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    io.shutdown().await.unwrap();
  };
  let cancel = async {
    tokio::task::yield_now().await;
    control.cancel();
  };
  tokio::time::timeout(Duration::from_secs(1), async {
    tokio::join!(read, cancel);
  })
  .await
  .unwrap();
}
