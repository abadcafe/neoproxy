//! module: exchange_timeout
//! responsibility: enforce per-exchange I/O inactivity deadlines
//! public operations: Timeouts, Control, TimedIo, UploadBody
//! data entities: Timeouts, Control, State, TimedIo, UploadBody
//! tests: exchange_timeout_tests.rs
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::AtomicWaker;
use http_body::{Body, Frame, SizeHint};

#[derive(Clone, Copy, Debug)]
pub(super) struct Timeouts {
  pub(super) send: Duration,
  pub(super) read: Duration,
}
impl Default for Timeouts {
  fn default() -> Self {
    Self {
      send: Duration::from_secs(10),
      read: Duration::from_secs(10),
    }
  }
}
const UPLOAD_DONE: u8 = 1;
const UPLOAD_FLUSHED: u8 = 2;
const READING: u8 = 4;
const RESPONSE_DONE: u8 = 8;
const CANCELLED: u8 = 16;

#[derive(Default)]
struct State {
  // Only exchange configuration changes take this lock. I/O polls use
  // the driver's cached configuration and its exclusively owned
  // timers.
  settings: Mutex<Option<Timeouts>>,
  generation: AtomicU64,
  flags: AtomicU8,
  reader: AtomicWaker,
  writer: AtomicWaker,
  upload: AtomicWaker,
}
#[derive(Clone, Default)]
pub(super) struct Control(Arc<State>);
impl Control {
  pub(super) fn start(&self, settings: Timeouts) {
    self.configure(Some(settings));
  }

  fn configure(&self, settings: Option<Timeouts>) {
    let mut current =
      self.0.settings.lock().expect("exchange settings poisoned");
    *current = settings;
    self.0.flags.store(0, Ordering::Release);
    self.0.generation.fetch_add(1, Ordering::Release);
  }

  pub(super) fn cancel(&self) {
    self.0.flags.fetch_or(CANCELLED, Ordering::AcqRel);
    self.0.reader.wake();
    self.0.writer.wake();
    self.0.upload.wake();
  }

  pub(super) fn upload_flushed(&self) -> bool {
    self.0.flags.load(Ordering::Acquire) & UPLOAD_FLUSHED != 0
  }

  pub(super) fn upload_complete(&self) {
    self.0.flags.fetch_or(UPLOAD_DONE, Ordering::AcqRel);
    self.0.reader.wake();
  }

  pub(super) fn response_started(&self) {
    self.0.flags.fetch_or(READING, Ordering::AcqRel);
    self.0.reader.wake();
  }

  pub(super) fn response_complete(&self) {
    self
      .0
      .flags
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |flags| {
        Some((flags | RESPONSE_DONE) & !READING)
      })
      .expect("unconditional state update");
  }

  pub(super) fn disable(&self) {
    self.configure(None);
  }
}
fn pending_timeout<T>(
  timer: &mut Option<Pin<Box<tokio::time::Sleep>>>,
  duration: Duration,
  cx: &mut Context<'_>,
  phase: &'static str,
) -> Poll<std::io::Result<T>> {
  let timer =
    timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(duration)));
  if timer.as_mut().poll(cx).is_ready() {
    Poll::Ready(Err(std::io::Error::new(
      std::io::ErrorKind::TimedOut,
      phase,
    )))
  } else {
    Poll::Pending
  }
}
pub(super) struct TimedIo<I> {
  inner: I,
  control: Control,
  generation: u64,
  settings: Option<Timeouts>,
  read_timer: Option<Pin<Box<tokio::time::Sleep>>>,
  write_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl<I> TimedIo<I> {
  fn refresh(&mut self) {
    if self.generation
      != self.control.0.generation.load(Ordering::Acquire)
    {
      let settings = self
        .control
        .0
        .settings
        .lock()
        .expect("exchange settings poisoned");
      self.settings = *settings;
      self.generation =
        self.control.0.generation.load(Ordering::Acquire);
      self.read_timer = None;
      self.write_timer = None;
    }
  }

  pub(super) fn new(inner: I, control: Control) -> Self {
    Self {
      inner,
      control,
      generation: 0,
      settings: None,
      read_timer: None,
      write_timer: None,
    }
  }
}
impl<I: hyper::rt::Read + Unpin> hyper::rt::Read for TimedIo<I> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<std::io::Result<()>> {
    self.refresh();
    self.control.0.reader.register(cx.waker());
    if self.control.0.flags.load(Ordering::Acquire) & CANCELLED != 0 {
      return Poll::Ready(Err(
        std::io::ErrorKind::ConnectionAborted.into(),
      ));
    }
    let result = Pin::new(&mut self.inner).poll_read(cx, buf);
    if result.is_ready() {
      self.read_timer = None;
      return result;
    }
    if self.control.0.flags.load(Ordering::Acquire) & READING != 0
      && let Some(settings) = self.settings
    {
      return pending_timeout(
        &mut self.read_timer,
        settings.read,
        cx,
        "upstream read inactivity timeout",
      );
    }
    self.read_timer = None;
    result
  }
}
impl<I: hyper::rt::Write + Unpin> hyper::rt::Write for TimedIo<I> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bytes: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    self.refresh();
    self.control.0.writer.register(cx.waker());
    if self.control.0.flags.load(Ordering::Acquire) & CANCELLED != 0 {
      return Poll::Ready(Err(
        std::io::ErrorKind::ConnectionAborted.into(),
      ));
    }
    let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
    if result.is_ready() {
      self.write_timer = None;
      return result;
    }
    if let Some(settings) = self.settings {
      return pending_timeout(
        &mut self.write_timer,
        settings.send,
        cx,
        "upstream send inactivity timeout",
      );
    }
    result
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    self.refresh();
    self.control.0.writer.register(cx.waker());
    if self.control.0.flags.load(Ordering::Acquire) & CANCELLED != 0 {
      return Poll::Ready(Err(
        std::io::ErrorKind::ConnectionAborted.into(),
      ));
    }
    let result = Pin::new(&mut self.inner).poll_flush(cx);
    if result.is_ready() {
      self.write_timer = None;
      // Body EOF alone is insufficient: Hyper may still have buffered
      // request bytes. Start response waiting only after they flush.
      if self.control.0.flags.load(Ordering::Acquire) & UPLOAD_DONE != 0
      {
        self
          .control
          .0
          .flags
          .fetch_update(Ordering::AcqRel, Ordering::Acquire, |flags| {
            Some(
              flags
                | UPLOAD_FLUSHED
                | if flags & RESPONSE_DONE == 0 { READING } else { 0 },
            )
          })
          .expect("unconditional state update");
        self.control.0.reader.wake();
      }
      return result;
    }
    if let Some(settings) = self.settings {
      return pending_timeout(
        &mut self.write_timer,
        settings.send,
        cx,
        "upstream send inactivity timeout",
      );
    }
    result
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}
pub(super) struct UploadBody {
  inner: crate::http_message::RequestBody,
  control: Control,
}
impl UploadBody {
  pub(super) fn wrap(
    inner: crate::http_message::RequestBody,
    control: Control,
  ) -> crate::http_message::RequestBody {
    if inner.is_end_stream() {
      control.upload_complete();
    }
    crate::http_message::RequestBody::new(Self { inner, control })
  }
}
impl Body for UploadBody {
  type Data = bytes::Bytes;
  type Error = anyhow::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.control.0.upload.register(cx.waker());
    if self.control.0.flags.load(Ordering::Acquire) & CANCELLED != 0 {
      return Poll::Ready(Some(Err(
        std::io::Error::from(std::io::ErrorKind::ConnectionAborted)
          .into(),
      )));
    }
    let result = Pin::new(&mut self.inner).poll_frame(cx);
    if matches!(&result, Poll::Ready(Some(Ok(frame))) if frame.is_trailers())
      || matches!(result, Poll::Ready(None))
      || self.inner.is_end_stream()
    {
      self.control.upload_complete();
    }
    result
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}
