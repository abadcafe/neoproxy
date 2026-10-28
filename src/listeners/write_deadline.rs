//! module: write_deadline
//! responsibility: bound blocked transport writes until HTTP upgrade
//! public operations: TimedIo::new, Control::disable
//! data entities: TimedIo, Control
//! tests: write_deadline_tests.rs
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[derive(Clone, Default)]
pub(super) struct Control(Arc<AtomicBool>);
impl Control {
  pub(super) fn disable(&self) {
    self.0.store(true, Ordering::Release);
  }
}
pub(super) struct TimedIo<I> {
  inner: I,
  reads: Option<crate::io_progress::Progress>,
  duration: Duration,
  timer: Option<Pin<Box<tokio::time::Sleep>>>,
  control: Control,
}
impl<I> TimedIo<I> {
  pub(super) fn new(
    inner: I,
    duration: Duration,
    control: Control,
  ) -> Self {
    Self { inner, duration, control, timer: None, reads: None }
  }

  pub(super) fn with_reads(
    mut self,
    reads: crate::io_progress::Progress,
  ) -> Self {
    self.reads = Some(reads);
    self
  }

  fn check<T>(
    &mut self,
    result: Poll<std::io::Result<T>>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<T>> {
    if result.is_ready() || self.control.0.load(Ordering::Acquire) {
      self.timer = None;
      return result;
    }
    let timer = self.timer.get_or_insert_with(|| {
      Box::pin(tokio::time::sleep(self.duration))
    });
    if timer.as_mut().poll(cx).is_ready() {
      Poll::Ready(Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "client write inactivity timeout",
      )))
    } else {
      Poll::Pending
    }
  }
}
impl<I: AsyncRead + Unpin> AsyncRead for TimedIo<I> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let before = buf.filled().len();
    let result = Pin::new(&mut self.inner).poll_read(cx, buf);
    if buf.filled().len() > before
      && let Some(reads) = &self.reads
    {
      reads.mark();
    }
    result
  }
}
impl<I: AsyncWrite + Unpin> AsyncWrite for TimedIo<I> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    data: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    let result = Pin::new(&mut self.inner).poll_write(cx, data);
    self.check(result, cx)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    let result = Pin::new(&mut self.inner).poll_flush(cx);
    self.check(result, cx)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    let result = Pin::new(&mut self.inner).poll_shutdown(cx);
    self.check(result, cx)
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    data: &[std::io::IoSlice<'_>],
  ) -> Poll<std::io::Result<usize>> {
    let result =
      Pin::new(&mut self.inner).poll_write_vectored(cx, data);
    self.check(result, cx)
  }
}
