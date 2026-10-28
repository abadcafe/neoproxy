//! module: read_progress
//! responsibility: observe per-stream QUIC reads beneath H3 framing
//! public operations: Registry, Connection, Opener, Bidi, Recv
//! data entities: Registry, Connection, Opener, Bidi, Recv
//! tests: HTTP/3 inactivity integration contracts
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Buf;
use h3::quic::{
  self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId,
};

use super::io_progress::{Progress, SendBuffer};

#[derive(Clone, Default)]
pub(super) struct Registry(Arc<Mutex<HashMap<StreamId, Progress>>>);
impl Registry {
  pub(super) fn get(&self, id: StreamId) -> Progress {
    self
      .0
      .lock()
      .expect("H3 read registry poisoned")
      .get(&id)
      .expect("opened stream is registered")
      .clone()
  }

  fn wrap(&self, stream: h3_quinn::BidiStream<SendBuffer>) -> Bidi {
    use quic::BidiStream;
    let (send, recv) = stream.split();
    let mut recv = Recv::new(recv);
    self
      .0
      .lock()
      .expect("H3 read registry poisoned")
      .insert(recv.id, recv.progress.clone());
    recv.registry = Some(self.clone());
    Bidi { send, recv }
  }
}
pub(in crate::plugins::upstream::client) struct Recv {
  inner: h3_quinn::RecvStream,
  id: StreamId,
  progress: Progress,
  registry: Option<Registry>,
}
impl Recv {
  fn new(inner: h3_quinn::RecvStream) -> Self {
    use quic::RecvStream;
    Self {
      id: inner.recv_id(),
      inner,
      progress: Progress::default(),
      registry: None,
    }
  }
}
impl Drop for Recv {
  fn drop(&mut self) {
    if let Some(registry) = &self.registry {
      registry
        .0
        .lock()
        .expect("H3 read registry poisoned")
        .remove(&self.id);
    }
  }
}
impl quic::RecvStream for Recv {
  type Buf = bytes::Bytes;

  fn poll_data(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
    let result = self.inner.poll_data(cx);
    if matches!(&result, Poll::Ready(Ok(Some(data))) if data.has_remaining())
    {
      self.progress.mark();
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
pub(in crate::plugins::upstream::client) struct Bidi {
  send: h3_quinn::SendStream<SendBuffer>,
  recv: Recv,
}
impl quic::BidiStream<SendBuffer> for Bidi {
  type RecvStream = Recv;
  type SendStream = h3_quinn::SendStream<SendBuffer>;

  fn split(self) -> (Self::SendStream, Self::RecvStream) {
    (self.send, self.recv)
  }
}
impl quic::RecvStream for Bidi {
  type Buf = bytes::Bytes;

  fn poll_data(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
    self.recv.poll_data(cx)
  }

  fn stop_sending(&mut self, code: u64) {
    self.recv.stop_sending(code);
  }

  fn recv_id(&self) -> StreamId {
    self.recv.recv_id()
  }
}
impl quic::SendStream<SendBuffer> for Bidi {
  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    self.send.poll_ready(cx)
  }

  fn poll_finish(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), StreamErrorIncoming>> {
    self.send.poll_finish(cx)
  }

  fn reset(&mut self, code: u64) {
    self.send.reset(code);
  }

  fn send_data<D: Into<h3::quic::WriteBuf<SendBuffer>>>(
    &mut self,
    data: D,
  ) -> Result<(), StreamErrorIncoming> {
    self.send.send_data(data)
  }

  fn send_id(&self) -> StreamId {
    self.send.send_id()
  }
}
pub(super) struct Connection {
  inner: h3_quinn::Connection,
  registry: Registry,
}
impl Connection {
  pub(super) fn new(
    connection: quinn::Connection,
    registry: Registry,
  ) -> Self {
    Self { inner: h3_quinn::Connection::new(connection), registry }
  }
}
#[derive(Clone)]
pub(super) struct Opener {
  inner: h3_quinn::OpenStreams,
  registry: Registry,
}
macro_rules! impl_open {
  ($ty:ty) => {
    impl quic::OpenStreams<SendBuffer> for $ty {
      type BidiStream = Bidi;
      type SendStream = h3_quinn::SendStream<SendBuffer>;

      fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
      ) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        self
          .inner
          .poll_open_bidi(cx)
          .map(|result| result.map(|stream| self.registry.wrap(stream)))
      }

      fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
      ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
      }

      fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<SendBuffer>::close(
          &mut self.inner,
          code,
          reason,
        );
      }
    }
  };
}
impl_open!(Connection);
impl_open!(Opener);
impl quic::Connection<SendBuffer> for Connection {
  type OpenStreams = Opener;
  type RecvStream = Recv;

  fn poll_accept_bidi(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Bidi, ConnectionErrorIncoming>> {
    self
      .inner
      .poll_accept_bidi(cx)
      .map(|result| result.map(|stream| self.registry.wrap(stream)))
  }

  fn poll_accept_recv(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Recv, ConnectionErrorIncoming>> {
    quic::Connection::<SendBuffer>::poll_accept_recv(
      &mut self.inner,
      cx,
    )
    .map(|result| result.map(Recv::new))
  }

  fn opener(&self) -> Opener {
    Opener {
      inner: quic::Connection::<SendBuffer>::opener(&self.inner),
      registry: self.registry.clone(),
    }
  }
}
