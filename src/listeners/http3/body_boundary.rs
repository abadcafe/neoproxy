//! module: listeners::http3::body_boundary
//! responsibility: complete the incoming body before releasing its
//! declared final bytes public operations: BodyBoundary::new, Body
//! implementation data entities: BodyBoundary
//! tests: body_boundary_tests.rs
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body, Frame};

/// Keeps the final data frame until transport completion. Earlier
/// frames stream immediately. A length-delimited consumer may drop its
/// body once it has read the declared bytes; it must not thereby cancel
/// an unfinished H3 receive stream.
pub(super) struct BodyBoundary<B> {
  inner: B,
  remaining: Option<u64>,
  final_data: Option<Bytes>,
  trailers: Option<HeaderMap>,
  done: bool,
}

impl<B> BodyBoundary<B> {
  pub(super) fn new(inner: B, content_length: Option<u64>) -> Self {
    Self {
      inner,
      remaining: content_length,
      final_data: None,
      trailers: None,
      done: false,
    }
  }

  fn fail(
    &mut self,
    error: anyhow::Error,
  ) -> Poll<Option<Result<Frame<Bytes>, anyhow::Error>>> {
    self.done = true;
    self.final_data = None;
    self.trailers = None;
    Poll::Ready(Some(Err(error)))
  }
}

impl<B: Body<Data = Bytes> + Unpin> Body for BodyBoundary<B>
where
  B::Error: Into<anyhow::Error>,
{
  type Data = Bytes;
  type Error = anyhow::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, anyhow::Error>>> {
    loop {
      if self.done {
        return Poll::Ready(
          self
            .final_data
            .take()
            .map(Frame::data)
            .or_else(|| self.trailers.take().map(Frame::trailers))
            .map(Ok),
        );
      }
      match Pin::new(&mut self.inner).poll_frame(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Some(Err(error))) => {
          return self.fail(error.into());
        }
        Poll::Ready(None) => {
          if self.remaining.is_some_and(|remaining| remaining > 0) {
            return self.fail(anyhow::anyhow!(
              "body shorter than Content-Length"
            ));
          }
          self.done = true;
        }
        Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
          Ok(data) => {
            if self.trailers.is_some() {
              return self
                .fail(anyhow::anyhow!("body data after trailers"));
            }
            if data.is_empty() {
              continue;
            }
            if let Some(remaining) = &mut self.remaining {
              let Some(next) = remaining.checked_sub(data.len() as u64)
              else {
                return self.fail(anyhow::anyhow!(
                  "body exceeds Content-Length"
                ));
              };
              *remaining = next;
              if next == 0 {
                self.final_data = Some(data);
                continue;
              }
            }
            return Poll::Ready(Some(Ok(Frame::data(data))));
          }
          Err(frame) => {
            if let Ok(trailers) = frame.into_trailers()
              && self.trailers.replace(trailers).is_some()
            {
              return self
                .fail(anyhow::anyhow!("duplicate body trailers"));
            }
          }
        },
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    self.done && self.final_data.is_none() && self.trailers.is_none()
  }
}
