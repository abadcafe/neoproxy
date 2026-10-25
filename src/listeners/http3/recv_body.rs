//! module: recv_body
//! responsibilities: expose an HTTP/3 request stream as a streaming
//! HTTP body public operations: H3RecvBody::new, http_body::Body
//! data entities: H3RecvBody, ReceiveState
//! tests: recv_body_tests.rs; HTTP/3 process regressions

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame};

enum ReceiveState {
  Data,
  Trailers,
  Done,
}

pub(super) struct H3RecvBody {
  stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
  state: ReceiveState,
}

impl H3RecvBody {
  pub(super) fn new(
    stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
  ) -> Self {
    Self { stream, state: ReceiveState::Data }
  }
}

impl Body for H3RecvBody {
  type Data = Bytes;
  type Error = h3::error::StreamError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
    loop {
      match self.state {
        ReceiveState::Data => match self.stream.poll_recv_data(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Ok(Some(mut data))) => {
            return Poll::Ready(Some(Ok(Frame::data(
              data.copy_to_bytes(data.remaining()),
            ))));
          }
          Poll::Ready(Ok(None)) => self.state = ReceiveState::Trailers,
          Poll::Ready(Err(error)) => {
            self.state = ReceiveState::Done;
            return Poll::Ready(Some(Err(error)));
          }
        },
        ReceiveState::Trailers => match self
          .stream
          .poll_recv_trailers(cx)
        {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(result) => {
            self.state = ReceiveState::Done;
            return Poll::Ready(match result {
              Ok(Some(trailers)) => Some(Ok(Frame::trailers(trailers))),
              Ok(None) => None,
              Err(error) => Some(Err(error)),
            });
          }
        },
        ReceiveState::Done => return Poll::Ready(None),
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    matches!(self.state, ReceiveState::Done)
  }
}
