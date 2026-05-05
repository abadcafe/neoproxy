use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use bytes::{Buf, Bytes};
use h3::error::StreamError;
use tokio::io;

/// State for an in-progress send_data or finish operation.
/// Generic over the send stream type S.
///
/// The boxed futures require `Send + Sync` bounds because
/// `H3ServerBidiStream` must be `Sync` for use with
/// `http::Extensions::insert`. The `Sync` bound propagates through:
/// `H3ServerBidiStream` contains `SendState`, which contains these
/// boxed futures. Without `+ Sync` on the futures, the
/// `H3ServerBidiStream` type would not be `Sync`, preventing it from
/// being stored in `http::Extensions` or sent through oneshot channels
/// in the `H3OnUpgrade` mechanism.
enum SendState<S> {
  Idle,
  Sending {
    fut: Pin<
      Box<
        dyn Future<Output = (S, Result<(), StreamError>)> + Send + Sync,
      >,
    >,
    len: usize,
  },
  Finishing {
    fut: Pin<
      Box<
        dyn Future<Output = (S, Result<(), StreamError>)> + Send + Sync,
      >,
    >,
  },
}

/// HTTP/3 bidirectional stream wrapper, generic over send/recv stream
/// types.
///
/// Combines h3 SendStream and RecvStream into a single type
/// implementing AsyncRead + AsyncWrite, enabling use with
/// `tokio::io::copy_bidirectional`.
///
/// Works with both `h3::client::RequestStream` and
/// `h3::server::RequestStream` since both have identical `send_data()`,
/// `finish()`, and `poll_recv_data()` APIs.
pub struct H3BidirectionalStream<S: 'static, R> {
  send: Option<S>,
  recv: R,
  recv_buf: Option<Bytes>,
  send_state: SendState<S>,
}

impl<S: 'static, R> H3BidirectionalStream<S, R> {
  pub fn new(send: S, recv: R) -> Self {
    Self {
      send: Some(send),
      recv,
      recv_buf: None,
      send_state: SendState::Idle,
    }
  }
}

// SAFETY: H3BidirectionalStream does not contain any self-referential
// data. The fields are all owned data: Option<S>, R, Option<Bytes>, and
// SendState<S>. The SendState enum contains boxed futures, but those
// futures own their data (including the send stream S), not borrow from
// self.
impl<S: 'static, R> Unpin for H3BidirectionalStream<S, R> {}

/// Macro to implement AsyncWrite for H3BidirectionalStream with a
/// specific send stream type. Both h3::client::RequestStream and
/// h3::server::RequestStream have identical send_data()/finish()
/// signatures but are different types, so we use a macro to avoid
/// duplication.
macro_rules! impl_h3_async_write {
  ($send_type:ty) => {
    impl<R> io::AsyncWrite for H3BidirectionalStream<$send_type, R> {
      fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
      ) -> Poll<Result<usize, std::io::Error>> {
        loop {
          match &mut self.send_state {
            SendState::Idle => {
              let mut send = self
                .send
                .take()
                .expect(
                  "internal error: send stream invariant violated in poll_write Idle state \
                   - this is a bug, please report at https://github.com/example/neoproxy/issues",
                );
              let data = Bytes::copy_from_slice(buf);
              let len = data.len();
              let fut = Box::pin(async move {
                let result = send.send_data(data).await;
                (send, result)
              });
              self.send_state = SendState::Sending { fut, len };
            }
            SendState::Sending { fut, len } => {
              let len = *len;
              match fut.as_mut().poll(cx) {
                Poll::Ready((send, result)) => {
                  self.send = Some(send);
                  self.send_state = SendState::Idle;
                  return match result {
                    Ok(()) => Poll::Ready(Ok(len)),
                    Err(e) if e.is_h3_no_error() => Poll::Ready(Ok(len)),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                  };
                }
                Poll::Pending => return Poll::Pending,
              }
            }
            SendState::Finishing { .. } => {
              return Poll::Ready(Err(std::io::Error::other(
                "stream is shutting down",
              )));
            }
          }
        }
      }

      fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
      ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
      }

      fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
      ) -> Poll<Result<(), std::io::Error>> {
        loop {
          match &mut self.send_state {
            SendState::Idle => {
              let mut send = self
                .send
                .take()
                .expect(
                  "internal error: send stream invariant violated in poll_shutdown Idle state \
                   - this is a bug, please report at https://github.com/example/neoproxy/issues",
                );
              let fut = Box::pin(async move {
                let result = send.finish().await;
                (send, result)
              });
              self.send_state = SendState::Finishing { fut };
            }
            SendState::Sending { fut, .. } => {
              match fut.as_mut().poll(cx) {
                Poll::Ready((send, _result)) => {
                  self.send = Some(send);
                  self.send_state = SendState::Idle;
                }
                Poll::Pending => return Poll::Pending,
              }
            }
            SendState::Finishing { fut } => match fut.as_mut().poll(cx) {
              Poll::Ready((send, result)) => {
                self.send = Some(send);
                self.send_state = SendState::Idle;
                return result.map_err(std::io::Error::other).into();
              }
              Poll::Pending => return Poll::Pending,
            },
          }
        }
      }
    }
  };
}

/// Macro to implement AsyncRead for H3BidirectionalStream with a
/// specific recv stream type.
macro_rules! impl_h3_async_read {
  ($send_type:ty, $recv_type:ty) => {
    impl io::AsyncRead
      for H3BidirectionalStream<$send_type, $recv_type>
    {
      fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut io::ReadBuf<'_>,
      ) -> Poll<Result<(), std::io::Error>> {
        // Return buffered data first
        if let Some(data) = self.recv_buf.take() {
          let n = std::cmp::min(data.len(), buf.remaining());
          buf.put_slice(&data[..n]);
          if n < data.len() {
            self.recv_buf = Some(data.slice(n..));
          }
          return Poll::Ready(Ok(()));
        }

        // Poll for new data
        match self.recv.poll_recv_data(cx) {
          Poll::Ready(Ok(Some(mut data))) => {
            let bytes = data.copy_to_bytes(data.remaining());
            let n = std::cmp::min(bytes.len(), buf.remaining());
            buf.put_slice(&bytes[..n]);
            if n < bytes.len() {
              self.recv_buf = Some(bytes.slice(n..));
            }
            Poll::Ready(Ok(()))
          }
          Poll::Ready(Ok(None)) => Poll::Ready(Ok(())), // EOF
          Poll::Ready(Err(e)) => {
            Poll::Ready(Err(std::io::Error::other(e)))
          }
          Poll::Pending => Poll::Pending,
        }
      }
    }
  };
}

// ---- Client-side (used by http3_chain for outbound connections) ----

impl_h3_async_write!(
  h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>
);

impl_h3_async_read!(
  h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  h3::client::RequestStream<h3_quinn::RecvStream, Bytes>
);

// ---- Server-side (used by H3 listener via H3OnUpgrade) ----

impl_h3_async_write!(
  h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>
);

impl_h3_async_read!(
  h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  h3::server::RequestStream<h3_quinn::RecvStream, Bytes>
);

// ---- Type aliases for convenience ----

/// Client-side H3 bidirectional stream for outbound proxy connections.
///
/// Used by `http3_chain` service when acting as a client connecting to
/// upstream HTTP/3 proxies. The stream wraps the client-side H3 request
/// stream obtained from `h3::client::SendRequest::send_request()`.
///
/// # Data Flow Direction
/// - **Send half**: Data written via `AsyncWrite` goes to the upstream
///   proxy
/// - **Recv half**: Data read via `AsyncRead` comes from the upstream
///   proxy
///
/// # Usage
/// ```ignore
/// let (send_stream, recv_stream) = proxy_stream.split();
/// let mut h3_stream = H3ClientBidiStream::new(send_stream, recv_stream);
/// tokio::io::copy_bidirectional(&mut client, &mut h3_stream).await?;
/// ```
pub type H3ClientBidiStream = H3BidirectionalStream<
  h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
>;

/// Server-side H3 bidirectional stream for inbound client connections.
///
/// Used by the H3 listener when receiving connections from downstream
/// clients. The stream wraps the server-side H3 request stream obtained
/// from `h3::server::Connection::accept()`. Delivered to the Service
/// via `H3OnUpgrade` after the listener sends the protocol response.
///
/// # Data Flow Direction
/// - **Send half**: Data written via `AsyncWrite` goes to the
///   downstream client
/// - **Recv half**: Data read via `AsyncRead` comes from the downstream
///   client
///
/// # Relation to h3 Types
/// - Send type: `h3::server::RequestStream<h3_quinn::SendStream<Bytes>,
///   Bytes>` (obtained via `.split()` on the full bidi stream)
/// - Recv type: `h3::server::RequestStream<h3_quinn::RecvStream,
///   Bytes>` (obtained via `.split()` on the full bidi stream)
///
/// # Usage
/// ```ignore
/// // In the H3 listener, after sending response:
/// let (send_stream, recv_stream) = h3_request_stream.split();
/// let bidi_stream = H3ServerBidiStream::new(send_stream, recv_stream);
/// // Send to Service via upgrade channel
/// upgrade_tx.send(Ok(bidi_stream))?;
/// ```
pub type H3ServerBidiStream = H3BidirectionalStream<
  h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
>;

#[cfg(test)]
mod tests {
  use tokio::io::{AsyncRead, AsyncWrite};

  use super::*;

  /// Compile-time verification that H3ServerBidiStream implements
  /// AsyncRead + AsyncWrite. This is critical because H3OnUpgrade
  /// delivers H3ServerBidiStream to the Service, which uses it
  /// with copy_bidirectional (requires both traits).
  fn assert_async_read_write<T: AsyncRead + AsyncWrite>() {}

  #[test]
  fn test_h3_server_bidi_stream_implements_async_read_write() {
    // This test verifies at compile time that the macro-generated
    // impls for the server-side variant are correct.
    assert_async_read_write::<H3ServerBidiStream>();
  }

  #[test]
  fn test_h3_client_bidi_stream_implements_async_read_write() {
    // Verify client-side variant still works after relocation.
    assert_async_read_write::<H3ClientBidiStream>();
  }

  /// Compile-time verification that H3ServerBidiStream is Unpin,
  /// required for Pin::new() in ClientStream's AsyncRead/AsyncWrite
  /// delegation.
  fn assert_unpin<T: Unpin>() {}

  #[test]
  fn test_h3_server_bidi_stream_is_unpin() {
    assert_unpin::<H3ServerBidiStream>();
  }

  #[test]
  fn test_h3_client_bidi_stream_is_unpin() {
    assert_unpin::<H3ClientBidiStream>();
  }

  /// Compile-time verification that H3ServerBidiStream is Send,
  /// required for use with tokio::spawn and cross-task boundaries.
  fn assert_send<T: Send>() {}

  #[test]
  fn test_h3_server_bidi_stream_is_send() {
    assert_send::<H3ServerBidiStream>();
  }

  #[test]
  fn test_h3_client_bidi_stream_is_send() {
    assert_send::<H3ClientBidiStream>();
  }

  /// Compile-time verification that H3ServerBidiStream is Sync.
  ///
  /// Required for use with `http::Extensions::insert` which requires
  /// `Send + Sync`. The `+ Sync` bound on the boxed futures in
  /// `SendState` ensures this trait is implemented. Without it,
  /// `H3ServerBidiStream` could not be stored in `http::Extensions`
  /// or sent through oneshot channels in `H3OnUpgrade`.
  fn assert_sync<T: Sync>() {}

  #[test]
  fn test_h3_server_bidi_stream_is_sync() {
    assert_sync::<H3ServerBidiStream>();
  }

  #[test]
  fn test_h3_client_bidi_stream_is_sync() {
    assert_sync::<H3ClientBidiStream>();
  }
}
