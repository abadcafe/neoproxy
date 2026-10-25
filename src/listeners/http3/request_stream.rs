//! module: request_stream
//! responsibility: cancel unfinished request streams before header
//! resolution public operations: CancellableStream::new, h3 stream
//! traits data entities: CancellableStream
//! tests: HTTP/3 shutdown process tests for incomplete headers and body
//! cancellation

use std::task::{Context, Poll};

use bytes::Bytes;
use h3::error::Code;
use h3::quic::{
  BidiStream, RecvStream, SendStream, StreamErrorIncoming, StreamId,
  WriteBuf,
};

pub(super) struct CancellableStream {
  inner: Option<h3_quinn::BidiStream<Bytes>>,
  finished: bool,
}

impl CancellableStream {
  pub(super) fn new(inner: h3_quinn::BidiStream<Bytes>) -> Self {
    Self { inner: Some(inner), finished: false }
  }
}

impl SendStream<Bytes> for CancellableStream {
  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    self.inner.as_mut().unwrap().poll_ready(cx)
  }

  fn send_data<D: Into<WriteBuf<Bytes>>>(
    &mut self,
    data: D,
  ) -> Result<(), StreamErrorIncoming> {
    self.inner.as_mut().unwrap().send_data(data)
  }

  fn poll_finish(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    let result = self.inner.as_mut().unwrap().poll_finish(cx);
    if matches!(result, Poll::Ready(Ok(()))) {
      self.finished = true;
    }
    result
  }

  fn reset(&mut self, code: u64) {
    self.inner.as_mut().unwrap().reset(code);
    self.finished = true;
  }

  fn send_id(&self) -> StreamId {
    self.inner.as_ref().unwrap().send_id()
  }
}

impl RecvStream for CancellableStream {
  type Buf = Bytes;

  fn poll_data(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
    self.inner.as_mut().unwrap().poll_data(cx)
  }

  fn stop_sending(&mut self, code: u64) {
    self.inner.as_mut().unwrap().stop_sending(code);
  }

  fn recv_id(&self) -> StreamId {
    self.inner.as_ref().unwrap().recv_id()
  }
}

impl BidiStream<Bytes> for CancellableStream {
  type RecvStream = h3_quinn::RecvStream;
  type SendStream = h3_quinn::SendStream<Bytes>;

  fn split(mut self) -> (Self::SendStream, Self::RecvStream) {
    // Consuming split transfers cancellation responsibility to the
    // ordinary response writer or the upgraded tunnel's I/O owner.
    self.inner.take().unwrap().split()
  }
}

impl Drop for CancellableStream {
  fn drop(&mut self) {
    // h3's unresolved RequestResolver has no request cancellation API.
    // Guard our stream before handing it to that parser. Do not reach
    // into its doc-hidden frame_stream or patch the third-party crate.
    // The Option permits a consuming split; every other method requires
    // an unsplit stream, so unwrap deliberately exposes invariant bugs.
    if !self.finished
      && let Some(stream) = &mut self.inner
    {
      stream.reset(Code::H3_REQUEST_CANCELLED.value());
    }
  }
}
