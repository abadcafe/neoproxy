//! Public buffer consumption is the transport's write-progress signal.
use std::time::Duration;

use bytes::{Buf, Bytes};

use crate::io_progress::{Progress, SendBuffer};

#[tokio::test(start_paused = true)]
async fn test_partial_writes_reset_timeout_without_finishing_frame() {
  let progress = Progress::default();
  let mut buffer =
    SendBuffer::tracked(Bytes::from_static(b"abc"), progress.clone());
  let sending = async {
    for _ in 0..3 {
      tokio::time::sleep(Duration::from_secs(9)).await;
      buffer.advance(1);
    }
  };
  assert!(
    progress.wait(sending, Duration::from_secs(10)).await.is_ok()
  );
}

#[tokio::test(start_paused = true)]
async fn test_no_write_progress_expires() {
  let progress = Progress::default();
  assert!(
    progress
      .wait(std::future::pending::<()>(), Duration::from_secs(10))
      .await
      .is_err()
  );
}

#[tokio::test(start_paused = true)]
async fn test_zero_byte_advance_does_not_extend_deadline() {
  let progress = Progress::default();
  let mut buffer =
    SendBuffer::tracked(Bytes::from_static(b"x"), progress.clone());
  let started = tokio::time::Instant::now();
  let sending = async {
    loop {
      tokio::time::sleep(Duration::from_secs(1)).await;
      buffer.advance(0);
    }
  };
  assert!(
    progress.wait(sending, Duration::from_secs(10)).await.is_err()
  );
  assert_eq!(started.elapsed(), Duration::from_secs(10));
}
