//! module: io_progress
//! responsibility: measure byte progress during active HTTP I/O
//! public operations: SendBuffer::{tracked,From, Buf},
//! Progress::{mark,poll_stalled,wait} data entities: SendBuffer,
//! Progress tests: io_progress_tests.rs
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

use bytes::{Buf, Bytes};

#[derive(Clone)]
pub(crate) struct Progress {
  epoch: tokio::time::Instant,
  last: Arc<AtomicU64>,
}
impl Default for Progress {
  fn default() -> Self {
    Self { epoch: tokio::time::Instant::now(), last: Arc::default() }
  }
}
impl Progress {
  fn last(&self) -> tokio::time::Instant {
    self.epoch + Duration::from_nanos(self.last.load(Ordering::Relaxed))
  }

  pub(crate) fn elapsed(&self) -> Duration {
    self.last().elapsed()
  }

  pub(crate) fn mark(&self) {
    let elapsed =
      self.epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    self.last.fetch_max(elapsed, Ordering::Relaxed);
  }

  pub(crate) fn poll_stalled(
    &self,
    timer: &mut Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    duration: Duration,
    cx: &mut std::task::Context<'_>,
  ) -> bool {
    let timer = timer.get_or_insert_with(|| {
      self.mark();
      Box::pin(tokio::time::sleep(duration))
    });
    let last = self.last();
    timer.as_mut().reset(last + duration);
    timer.as_mut().poll(cx).is_ready()
  }

  pub(crate) async fn wait<F: Future>(
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
      let last = self.last();
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
pub(crate) struct SendBuffer {
  bytes: Bytes,
  progress: Option<Progress>,
}
impl SendBuffer {
  pub(crate) fn tracked(bytes: Bytes, progress: Progress) -> Self {
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
      progress.mark();
    }
  }
}
