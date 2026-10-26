use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;

pin_project_lite::pin_project! {
  /// Adapt a concrete streaming body without an intermediate allocation.
  pub(crate) struct BytesBufBodyWrapper<B> {
    #[pin]
    inner: B,
  }
}

impl<B> BytesBufBodyWrapper<B> {
  pub(crate) fn new(inner: B) -> Self {
    Self { inner }
  }
}

impl<B> Body for BytesBufBodyWrapper<B>
where
  B: Body,
  B::Error: Error + Send + Sync + 'static,
{
  type Data = B::Data;
  type Error = anyhow::Error;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.project().inner.poll_frame(cx).map(|frame| {
      frame.map(|result| {
        result
          .map(|frame| match frame.into_trailers() {
            Ok(mut trailers) => {
              crate::hop_headers::strip_trailer_headers(&mut trailers);
              Frame::trailers(trailers)
            }
            Err(frame) => frame,
          })
          .map_err(Into::into)
      })
    })
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

pub(crate) type RequestBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub(crate) type ResponseBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub(crate) type Request = http::Request<RequestBody>;
pub(crate) type Response = http::Response<ResponseBody>;

/// Build an empty response with the given status code.
pub(crate) fn build_empty_response(
  status: http::StatusCode,
) -> Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = BytesBufBodyWrapper::new(empty);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = status;
  resp
}

/// Build an error response with the given status code and message.
pub(crate) fn build_error_response(
  status: http::StatusCode,
  message: &str,
) -> Response {
  let full =
    http_body_util::Full::new(bytes::Bytes::from(message.to_string()));
  let bytes_buf = BytesBufBodyWrapper::new(full);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = status;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("text/plain"),
  );
  resp
}
