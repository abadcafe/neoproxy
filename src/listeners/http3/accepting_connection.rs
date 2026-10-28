//! module: accepting_connection
//! responsibility: enforce the listener's new-request admission
//! boundary public operations: AcceptingConnection::new, h3 transport
//! traits data entities: AcceptingConnection, StreamOpener
//! tests: HTTP/3 shutdown process tests, including incomplete HEADERS
//! after GOAWAY

use std::task::{Context, Poll, ready};

use bytes::Bytes;
use h3::error::Code;
use h3::quic::{
  Connection, ConnectionErrorIncoming, OpenStreams, RecvStream,
  SendStream, StreamErrorIncoming,
};

use super::request_stream::CancellableStream;
use crate::shutdown::ShutdownHandle;

pub(super) struct StreamOpener(
  h3_quinn::OpenStreams,
  crate::h3_io_deadline::Controls,
);

pub(super) struct AcceptingConnection {
  inner: h3_quinn::Connection,
  shutdown: ShutdownHandle,
  controls: crate::h3_io_deadline::Controls,
}

impl AcceptingConnection {
  pub(super) fn new(
    connection: quinn::Connection,
    shutdown: ShutdownHandle,
    controls: crate::h3_io_deadline::Controls,
  ) -> Self {
    Self {
      inner: h3_quinn::Connection::new(connection),
      shutdown,
      controls,
    }
  }
}

impl Connection<Bytes> for AcceptingConnection {
  type OpenStreams = StreamOpener;
  type RecvStream = h3_quinn::RecvStream;

  fn poll_accept_recv(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
    <h3_quinn::Connection as Connection<Bytes>>::poll_accept_recv(
      &mut self.inner,
      cx,
    )
  }

  fn poll_accept_bidi(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
    // Reject at the QUIC stream boundary, before waiting for HEADERS.
    // GOAWAY alone is not admission control for an uncooperative peer.
    // Bound work per poll so a flood cannot monopolize this worker.
    const REJECTION_BATCH: usize = 32;
    for _ in 0..REJECTION_BATCH {
      let mut stream = ready!(self.inner.poll_accept_bidi(cx))?;
      if !self.shutdown.is_shutdown() {
        return Poll::Ready(Ok(CancellableStream::new(
          stream,
          &self.controls,
        )));
      }
      stream.stop_sending(Code::H3_REQUEST_REJECTED.value());
      stream.reset(Code::H3_REQUEST_REJECTED.value());
    }
    cx.waker().wake_by_ref();
    Poll::Pending
  }

  fn opener(&self) -> Self::OpenStreams {
    StreamOpener(
      <h3_quinn::Connection as Connection<Bytes>>::opener(&self.inner),
      self.controls.clone(),
    )
  }
}

impl OpenStreams<Bytes> for AcceptingConnection {
  type BidiStream = CancellableStream;
  type SendStream = h3_quinn::SendStream<Bytes>;

  fn poll_open_bidi(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
    self.inner.poll_open_bidi(cx).map(|result| {
      result
        .map(|stream| CancellableStream::new(stream, &self.controls))
    })
  }

  fn poll_open_send(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
    self.inner.poll_open_send(cx)
  }

  fn close(&mut self, code: Code, reason: &[u8]) {
    <h3_quinn::Connection as OpenStreams<Bytes>>::close(
      &mut self.inner,
      code,
      reason,
    );
  }
}

impl OpenStreams<Bytes> for StreamOpener {
  type BidiStream = CancellableStream;
  type SendStream = h3_quinn::SendStream<Bytes>;

  fn poll_open_bidi(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
    self.0.poll_open_bidi(cx).map(|result| {
      result.map(|stream| CancellableStream::new(stream, &self.1))
    })
  }

  fn poll_open_send(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
    self.0.poll_open_send(cx)
  }

  fn close(&mut self, code: Code, reason: &[u8]) {
    <h3_quinn::OpenStreams as OpenStreams<Bytes>>::close(
      &mut self.0,
      code,
      reason,
    );
  }
}
