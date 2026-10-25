//! module: h3_stream
//! responsibilities: adapt HTTP/3 tunnel halves to buffered
//! asynchronous I/O public operations: H3BidirectionalStream::new,
//! H3Send, H3Recv, H3ClientBidiStream, H3ServerBidiStream
//! data entities: SendState, SendFuture, H3BidirectionalStream
//! tests: h3_stream_tests.rs, h3_stream_read_tests.rs,
//! h3_stream_write_tests.rs

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum bytes accepted into one pending H3 send operation.
const SEND_BUFFER_CAPACITY: usize = 64 * 1024;

pub(crate) trait H3Send: Unpin + Send + Sync + 'static {
  fn send_data(
    &mut self,
    data: Bytes,
  ) -> impl Future<Output = std::io::Result<()>> + Send + Sync;
  fn finish(
    &mut self,
  ) -> impl Future<Output = std::io::Result<()>> + Send + Sync;
}

pub(crate) trait H3Recv: Unpin {
  fn poll_recv_data(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<Option<Bytes>>>;
}

type SendFuture<S> =
  Pin<Box<dyn Future<Output = (S, std::io::Result<()>)> + Send + Sync>>;
enum SendState<S> {
  Ready(S),
  Sending(SendFuture<S>),
  Finishing(SendFuture<S>),
  Closed,
}

pub(crate) struct H3BidirectionalStream<S, R> {
  send: SendState<S>,
  recv: R,
  buffered: Bytes,
}

impl<S, R> H3BidirectionalStream<S, R> {
  pub(crate) fn new(send: S, recv: R) -> Self {
    Self { send: SendState::Ready(send), recv, buffered: Bytes::new() }
  }
}

impl<S: H3Send, R: Unpin> AsyncWrite for H3BidirectionalStream<S, R> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    let this = self.get_mut();
    if matches!(this.send, SendState::Closed | SendState::Finishing(_))
    {
      return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
    }
    if buffer.is_empty() {
      return Poll::Ready(Ok(0));
    }
    std::task::ready!(Pin::new(&mut *this).poll_flush(cx))?;
    let SendState::Ready(mut send) =
      std::mem::replace(&mut this.send, SendState::Closed)
    else {
      // A successful flush must leave Ready; a violation is our own
      // state-machine bug and intentionally panics rather than hiding
      // it.
      unreachable!("flush left no writable stream")
    };
    let count = buffer.len().min(SEND_BUFFER_CAPACITY);
    let data = Bytes::copy_from_slice(&buffer[..count]);
    this.send = SendState::Sending(Box::pin(async move {
      let result = send.send_data(data).await;
      (send, result)
    }));
    // Accept into our bounded buffer now, never acknowledge an earlier
    // caller's buffer after returning Pending to that caller.
    Poll::Ready(Ok(count))
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    let this = self.get_mut();
    match &mut this.send {
      SendState::Ready(_) | SendState::Closed => Poll::Ready(Ok(())),
      SendState::Sending(future) => {
        let (send, result) =
          std::task::ready!(future.as_mut().poll(cx));
        this.send = if result.is_ok() {
          SendState::Ready(send)
        } else {
          SendState::Closed
        };
        Poll::Ready(result)
      }
      SendState::Finishing(_) => Pin::new(this).poll_shutdown(cx),
    }
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    let this = self.get_mut();
    loop {
      match &mut this.send {
        SendState::Closed => return Poll::Ready(Ok(())),
        SendState::Sending(_) => {
          std::task::ready!(Pin::new(&mut *this).poll_flush(cx))?;
        }
        SendState::Ready(_) => {
          let SendState::Ready(mut send) =
            std::mem::replace(&mut this.send, SendState::Closed)
          else {
            // This arm matched Ready immediately before replacing it;
            // failing this invariant is a programming bug: let it
            // panic.
            unreachable!("ready send state changed during shutdown")
          };
          this.send = SendState::Finishing(Box::pin(async move {
            let result = send.finish().await;
            (send, result)
          }));
        }
        SendState::Finishing(future) => {
          let (_, result) = std::task::ready!(future.as_mut().poll(cx));
          this.send = SendState::Closed;
          return Poll::Ready(result);
        }
      }
    }
  }
}

impl<S: Unpin, R: H3Recv> AsyncRead for H3BidirectionalStream<S, R> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let this = self.get_mut();
    if buffer.remaining() == 0 {
      return Poll::Ready(Ok(()));
    }
    loop {
      if !this.buffered.is_empty() {
        let count = buffer.remaining().min(this.buffered.len());
        buffer.put_slice(&this.buffered.split_to(count));
        return Poll::Ready(Ok(()));
      }
      match std::task::ready!(this.recv.poll_recv_data(cx))? {
        Some(data) => this.buffered = data,
        None => return Poll::Ready(Ok(())),
      }
    }
  }
}

macro_rules! impl_send {
  ($stream:ty) => {
    impl H3Send for $stream {
      async fn send_data(
        &mut self,
        data: Bytes,
      ) -> std::io::Result<()> {
        self.send_data(data).await.map_err(std::io::Error::other)
      }

      async fn finish(&mut self) -> std::io::Result<()> {
        self.finish().await.map_err(std::io::Error::other)
      }
    }
  };
}
macro_rules! impl_recv {
  ($stream:ty) => {
    impl H3Recv for $stream {
      fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
      ) -> Poll<std::io::Result<Option<Bytes>>> {
        match self.poll_recv_data(cx) {
          Poll::Ready(Ok(data)) => Poll::Ready(Ok(
            data
              .map(|mut bytes| bytes.copy_to_bytes(bytes.remaining())),
          )),
          Poll::Ready(Err(error)) if error.is_h3_no_error() => {
            Poll::Ready(Ok(None))
          }
          Poll::Ready(Err(error)) => {
            Poll::Ready(Err(std::io::Error::other(error)))
          }
          Poll::Pending => Poll::Pending,
        }
      }
    }
  };
}
impl_send!(
  h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>
);
impl_send!(
  h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>
);
impl_recv!(h3::client::RequestStream<h3_quinn::RecvStream, Bytes>);
impl_recv!(h3::server::RequestStream<h3_quinn::RecvStream, Bytes>);

pub(crate) type H3ClientBidiStream = H3BidirectionalStream<
  h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
>;
pub(crate) type H3ServerBidiStream = H3BidirectionalStream<
  h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
>;
