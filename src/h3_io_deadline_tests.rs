//! Test framed writes through the public QUIC transport traits.
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::quic::{
  SendStream, SendStreamUnframed, StreamErrorIncoming, StreamId,
  WriteBuf,
};

use crate::h3_io_deadline::Controls;

struct SlowSender {
  delay: Duration,
  timer: Option<Pin<Box<tokio::time::Sleep>>>,
  reset: Arc<AtomicBool>,
}
impl SendStream<Bytes> for SlowSender {
  fn poll_ready(
    &mut self,
    _: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    Poll::Ready(Ok(()))
  }

  fn send_data<D: Into<WriteBuf<Bytes>>>(
    &mut self,
    _: D,
  ) -> Result<(), StreamErrorIncoming> {
    panic!("adapter should send unframed bytes");
  }

  fn poll_finish(
    &mut self,
    _: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    Poll::Ready(Ok(()))
  }

  fn reset(&mut self, _: u64) {
    self.reset.store(true, Ordering::Relaxed);
  }

  fn send_id(&self) -> StreamId {
    0_u64.try_into().unwrap()
  }
}
impl SendStreamUnframed<Bytes> for SlowSender {
  fn poll_send<D: Buf>(
    &mut self,
    cx: &mut Context<'_>,
    data: &mut D,
  ) -> Poll<Result<usize, StreamErrorIncoming>> {
    let timer = self
      .timer
      .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.delay)));
    if timer.as_mut().poll(cx).is_pending() {
      return Poll::Pending;
    }
    self.timer = None;
    data.advance(1);
    Poll::Ready(Ok(1))
  }
}
#[tokio::test(start_paused = true)]
async fn test_slow_byte_progress_keeps_entire_frame_alive() {
  let controls = Controls::new(Duration::from_secs(1));
  let reset = Arc::new(AtomicBool::new(false));
  let mut stream = controls.register(SlowSender {
    delay: Duration::from_millis(900),
    timer: None,
    reset: reset.clone(),
  });
  stream
    .send_data(h3::proto::frame::Frame::Data(Bytes::from_static(
      b"hello",
    )))
    .unwrap();
  poll_fn(|cx| stream.poll_ready(cx)).await.unwrap();
  assert!(!reset.load(Ordering::Relaxed));
}
#[tokio::test(start_paused = true)]
async fn test_stall_resets_only_its_stream() {
  let controls = Controls::new(Duration::from_secs(1));
  let reset = Arc::new(AtomicBool::new(false));
  let mut stream = controls.register(SlowSender {
    delay: Duration::from_secs(2),
    timer: None,
    reset: reset.clone(),
  });
  stream
    .send_data(h3::proto::frame::Frame::Data(Bytes::from_static(
      b"hello",
    )))
    .unwrap();
  assert!(poll_fn(|cx| stream.poll_ready(cx)).await.is_err());
  assert!(reset.load(Ordering::Relaxed));
}
#[tokio::test(start_paused = true)]
async fn test_upgrade_disables_http_write_timeout() {
  let controls = Controls::new(Duration::from_secs(1));
  let reset = Arc::new(AtomicBool::new(false));
  let mut stream = controls.register(SlowSender {
    delay: Duration::from_secs(2),
    timer: None,
    reset: reset.clone(),
  });
  controls.take(stream.send_id()).disable();
  stream
    .send_data(h3::proto::frame::Frame::Data(Bytes::from_static(
      b"hello",
    )))
    .unwrap();
  poll_fn(|cx| stream.poll_finish(cx)).await.unwrap();
  assert!(!reset.load(Ordering::Relaxed));
}
