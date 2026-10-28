//! module: io_progress
//! responsibility: measure per-stream H3 byte progress
//! public operations: SendBuffer::{tracked,From, Buf}, Progress::wait
//! data entities: SendBuffer, Progress
//! tests: io_progress_tests.rs
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, Bytes};

#[derive(Clone)]
pub(in crate::plugins::upstream::client) struct Progress(
  Arc<Mutex<tokio::time::Instant>>,
);
impl Default for Progress {
  fn default() -> Self {
    Self(Arc::new(Mutex::new(tokio::time::Instant::now())))
  }
}
impl Progress {
  pub(super) fn mark(&self) {
    *self.0.lock().expect("H3 I/O progress poisoned") =
      tokio::time::Instant::now();
  }

  pub(super) fn poll_stalled(
    &self,
    timer: &mut Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    duration: Duration,
    cx: &mut std::task::Context<'_>,
  ) -> bool {
    let timer = timer.get_or_insert_with(|| {
      self.mark();
      Box::pin(tokio::time::sleep(duration))
    });
    let last = *self.0.lock().expect("H3 I/O progress poisoned");
    timer.as_mut().reset(last + duration);
    timer.as_mut().poll(cx).is_ready()
  }

  pub(super) async fn wait<F: Future>(
    &self,
    future: F,
    timeout: Duration,
  ) -> Result<F::Output, ()> {
    self.mark();
    tokio::pin!(future);
    let timer = tokio::time::sleep(timeout);
    tokio::pin!(timer);
    std::future::poll_fn(|cx| {
      if let Poll::Ready(result) = future.as_mut().poll(cx) {
        return Poll::Ready(Ok(result));
      }
      let last = *self.0.lock().expect("H3 write progress poisoned");
      timer.as_mut().reset(last + timeout);
      if timer.as_mut().poll(cx).is_ready() {
        Poll::Ready(Err(()))
      } else {
        Poll::Pending
      }
    })
    .await
  }
}
pub(in crate::plugins::upstream::client) struct SendBuffer {
  bytes: Bytes,
  progress: Option<Progress>,
}
impl SendBuffer {
  pub(super) fn tracked(bytes: Bytes, progress: Progress) -> Self {
    Self { bytes, progress: Some(progress) }
  }
}
impl From<Bytes> for SendBuffer {
  fn from(bytes: Bytes) -> Self {
    Self { bytes, progress: None }
  }
}
impl Buf for SendBuffer {
  fn remaining(&self) -> usize {
    self.bytes.remaining()
  }

  fn chunk(&self) -> &[u8] {
    self.bytes.chunk()
  }

  fn advance(&mut self, count: usize) {
    self.bytes.advance(count);
    if count > 0
      && let Some(progress) = &self.progress
    {
      *progress.0.lock().expect("H3 write progress poisoned") =
        tokio::time::Instant::now();
    }
  }
}
