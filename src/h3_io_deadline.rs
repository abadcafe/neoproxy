//! module: h3_io_deadline
//! responsibility: apply per-stream HTTP/3 I/O inactivity policy
//! public operations: Controls::{new,register,track_recv,take},
//! Control::{disable,reads}, QUIC stream traits
//! data entities: Controls, Control, State, TimedSend, TrackedRecv
//! tests: h3_io_deadline_tests.rs; listener timeout process contracts
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::quic::{
  SendStream, SendStreamUnframed, StreamErrorIncoming, StreamId,
  WriteBuf,
};

struct State {
  disabled: AtomicBool,
  reads: crate::io_progress::Progress,
}
#[derive(Clone)]
pub(crate) struct Control(Arc<State>);
impl Control {
  pub(crate) fn reads(&self) -> crate::io_progress::Progress {
    self.0.reads.clone()
  }

  pub(crate) fn disable(&self) {
    self.0.disabled.store(true, Ordering::Release);
  }
}
#[derive(Clone)]
pub(crate) struct Controls {
  duration: Duration,
  entries: Arc<Mutex<HashMap<StreamId, Weak<State>>>>,
}
impl Controls {
  pub(crate) fn new(duration: Duration) -> Self {
    Self { duration, entries: Arc::default() }
  }

  pub(crate) fn register<S: SendStreamUnframed<Bytes>>(
    &self,
    stream: S,
  ) -> TimedSend<S> {
    let control = Control(Arc::new(State {
      disabled: AtomicBool::new(false),
      reads: crate::io_progress::Progress::default(),
    }));
    let mut entries =
      self.entries.lock().expect("H3 write controls poisoned");
    entries.retain(|_, entry| entry.strong_count() > 0);
    entries.insert(stream.send_id(), Arc::downgrade(&control.0));
    TimedSend {
      inner: stream,
      pending: None,
      timer: None,
      control,
      duration: self.duration,
    }
  }

  pub(crate) fn track_recv<S: h3::quic::RecvStream>(
    &self,
    stream: S,
  ) -> TrackedRecv<S> {
    let id = stream.recv_id();
    let state = self
      .entries
      .lock()
      .expect("H3 controls poisoned")
      .get(&id)
      .and_then(Weak::upgrade)
      .expect("registered request stream");
    TrackedRecv { inner: stream, id, reads: state.reads.clone() }
  }

  pub(crate) fn take(&self, id: StreamId) -> Control {
    Control(
      self
        .entries
        .lock()
        .expect("H3 write controls poisoned")
        .remove(&id)
        .and_then(|entry| entry.upgrade())
        .expect("accepted stream has write control"),
    )
  }
}
pub(crate) struct TimedSend<S> {
  inner: S,
  pending: Option<WriteBuf<Bytes>>,
  timer: Option<Pin<Box<tokio::time::Sleep>>>,
  duration: Duration,
  control: Control,
}
impl<S: SendStreamUnframed<Bytes>> SendStream<Bytes> for TimedSend<S> {
  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    if let Some(data) = &mut self.pending {
      while data.has_remaining() {
        match self.inner.poll_send(cx, data) {
          Poll::Ready(Ok(0)) => {
            return Poll::Ready(Err(StreamErrorIncoming::Unknown(
              Box::new(std::io::Error::from(
                std::io::ErrorKind::WriteZero,
              )),
            )));
          }
          Poll::Ready(Ok(_)) => self.timer = None,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Pending => {
            if !self.control.0.disabled.load(Ordering::Acquire) {
              let timer = self.timer.get_or_insert_with(|| {
                Box::pin(tokio::time::sleep(self.duration))
              });
              if timer.as_mut().poll(cx).is_ready() {
                self
                  .inner
                  .reset(h3::error::Code::H3_REQUEST_CANCELLED.value());
                return Poll::Ready(Err(StreamErrorIncoming::Unknown(
                  Box::new(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "client write inactivity timeout",
                  )),
                )));
              }
            }
            return Poll::Pending;
          }
        }
      }
    }
    self.pending = None;
    self.timer = None;
    Poll::Ready(Ok(()))
  }

  fn send_data<D: Into<WriteBuf<Bytes>>>(
    &mut self,
    data: D,
  ) -> Result<(), StreamErrorIncoming> {
    assert!(
      self.pending.is_none(),
      "H3 sender must poll ready before queuing a frame"
    );
    self.pending = Some(data.into());
    Ok(())
  }

  fn poll_finish(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    ready!(self.poll_ready(cx))?;
    self.inner.poll_finish(cx)
  }

  fn reset(&mut self, code: u64) {
    self.pending = None;
    self.timer = None;
    self.inner.reset(code);
  }

  fn send_id(&self) -> StreamId {
    self.inner.send_id()
  }
}

/// Observe bytes before DATA/trailer framing, including fragmented
/// trailers.
pub(crate) struct TrackedRecv<S> {
  inner: S,
  id: StreamId,
  reads: crate::io_progress::Progress,
}
impl<S: h3::quic::RecvStream> h3::quic::RecvStream for TrackedRecv<S> {
  type Buf = S::Buf;

  fn poll_data(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
    let result = self.inner.poll_data(cx);
    if let Poll::Ready(Ok(Some(bytes))) = &result
      && bytes.has_remaining()
    {
      self.reads.mark();
    }
    result
  }

  fn stop_sending(&mut self, code: u64) {
    self.inner.stop_sending(code);
  }

  fn recv_id(&self) -> StreamId {
    self.id
  }
}
