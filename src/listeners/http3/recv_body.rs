use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame};

/// HTTP/3 request body adapter for receiving data from H3 streams.
pub(super) struct H3RecvBody {
  stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl H3RecvBody {
  pub(super) fn new(
    stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
  ) -> Self {
    Self { stream }
  }
}

// SAFETY: H3RecvBody owns its stream and contains no self-referential
// data.
impl Unpin for H3RecvBody {}

impl Body for H3RecvBody {
  type Data = Bytes;
  type Error = h3::error::StreamError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.stream).poll_recv_data(cx) {
      Poll::Ready(Ok(Some(mut data))) => {
        let bytes = data.copy_to_bytes(data.remaining());
        Poll::Ready(Some(Ok(Frame::data(bytes))))
      }
      Poll::Ready(Ok(None)) => Poll::Ready(None),
      Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
      Poll::Pending => Poll::Pending,
    }
  }
}
