//! module: exchange_timeout
//! responsibility: enforce per-exchange I/O inactivity deadlines
//! public operations: Timeouts, Control, TimedIo, UploadBody
//! data entities: Timeouts, Control, State, TimedIo, UploadBody
//! tests: exchange_timeout_tests.rs
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

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
#[derive(Default)]
struct State {
  settings: Option<Timeouts>,
  upload_done: bool,
  upload_flushed: bool,
  reading: bool,
  response_done: bool,
  read_timer: Option<Pin<Box<tokio::time::Sleep>>>,
  write_timer: Option<Pin<Box<tokio::time::Sleep>>>,
  reader: Option<Waker>,
  writer: Option<Waker>,
  upload: Option<Waker>,
  cancelled: bool,
}
#[derive(Clone, Default)]
pub(super) struct Control(Arc<Mutex<State>>);
impl Control {
  pub(super) fn start(&self, settings: Timeouts) {
    *self.0.lock().expect("exchange timer poisoned") =
      State { settings: Some(settings), ..State::default() };
  }

  /// Cancel an abandoned exchange before closing its HTTP driver.
  /// Wake every possible wait so cleanup never relies on peer traffic.
  pub(super) fn cancel(&self) {
    let mut state = self.0.lock().expect("exchange timer poisoned");
    state.cancelled = true;
    for waker in
      [state.reader.take(), state.writer.take(), state.upload.take()]
        .into_iter()
        .flatten()
    {
      waker.wake();
    }
  }

  fn poll_cancelled(&self, cx: &Context<'_>) -> bool {
    let mut state = self.0.lock().expect("exchange timer poisoned");
    state.reader = Some(cx.waker().clone());
    state.cancelled
  }

  pub(super) fn upload_flushed(&self) -> bool {
    self.0.lock().expect("exchange timer poisoned").upload_flushed
  }

  pub(super) fn upload_complete(&self) {
    let mut state = self.0.lock().expect("exchange timer poisoned");
    state.upload_done = true;
    if let Some(waker) = state.reader.take() {
      waker.wake();
    }
  }

  pub(super) fn response_started(&self) {
    let mut state = self.0.lock().expect("exchange timer poisoned");
    state.reading = true;
    if let Some(waker) = state.reader.take() {
      waker.wake();
    }
  }

  pub(super) fn response_complete(&self) {
    let mut state = self.0.lock().expect("exchange timer poisoned");
    state.response_done = true;
    state.reading = false;
    state.read_timer = None;
  }

  pub(super) fn disable(&self) {
    *self.0.lock().expect("exchange timer poisoned") = State::default();
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
}
impl<I> TimedIo<I> {
  pub(super) fn new(inner: I, control: Control) -> Self {
    Self { inner, control }
  }
}
impl<I: hyper::rt::Read + Unpin> hyper::rt::Read for TimedIo<I> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<std::io::Result<()>> {
    if self.control.poll_cancelled(cx) {
      return Poll::Ready(Err(
        std::io::ErrorKind::ConnectionAborted.into(),
      ));
    }
    let result = Pin::new(&mut self.inner).poll_read(cx, buf);
    let mut state =
      self.control.0.lock().expect("exchange timer poisoned");
    if result.is_ready() {
      state.read_timer = None;
      return result;
    }
    state.reader = Some(cx.waker().clone());
    if state.reading
      && let Some(settings) = state.settings
    {
      return pending_timeout(
        &mut state.read_timer,
        settings.read,
        cx,
        "upstream read inactivity timeout",
      );
    }
    result
  }
}
impl<I: hyper::rt::Write + Unpin> hyper::rt::Write for TimedIo<I> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bytes: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    {
      let mut state =
        self.control.0.lock().expect("exchange timer poisoned");
      if state.cancelled {
        return Poll::Ready(Err(
          std::io::ErrorKind::ConnectionAborted.into(),
        ));
      }
      state.writer = Some(cx.waker().clone());
    }
    let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
    let mut state =
      self.control.0.lock().expect("exchange timer poisoned");
    if result.is_ready() {
      state.write_timer = None;
      return result;
    }
    if let Some(settings) = state.settings {
      return pending_timeout(
        &mut state.write_timer,
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
    {
      let mut state =
        self.control.0.lock().expect("exchange timer poisoned");
      if state.cancelled {
        return Poll::Ready(Err(
          std::io::ErrorKind::ConnectionAborted.into(),
        ));
      }
      state.writer = Some(cx.waker().clone());
    }
    let result = Pin::new(&mut self.inner).poll_flush(cx);
    let mut state =
      self.control.0.lock().expect("exchange timer poisoned");
    if result.is_ready() {
      state.write_timer = None;
      // Body EOF alone is insufficient: Hyper may still have buffered
      // request bytes. Start response waiting only after they flush.
      if state.upload_done {
        state.upload_flushed = true;
      }
      if state.upload_done && !state.response_done {
        state.reading = true;
        if let Some(waker) = state.reader.take() {
          waker.wake();
        }
      }
      return result;
    }
    if let Some(settings) = state.settings {
      return pending_timeout(
        &mut state.write_timer,
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
    {
      let mut state =
        self.control.0.lock().expect("exchange timer poisoned");
      if state.cancelled {
        return Poll::Ready(Some(Err(
          std::io::Error::from(std::io::ErrorKind::ConnectionAborted)
            .into(),
        )));
      }
      state.upload = Some(cx.waker().clone());
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
